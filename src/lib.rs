mod fbei;

use crate::fbei::EnvInterface;
use async_std::task;
use evmc_vm::ffi::{evmc_call_kind, evmc_status_code};
use fbei::EnvironmentInterface;
use log::{debug, error, info, log_enabled, Level};
use lru::LruCache;
use once_cell::sync::Lazy;
use std::sync::{Arc, Mutex, Once};
use std::{env, error, fmt, time::Instant};
use wasmtime::{
    Caller, Config, Engine, Global, GlobalType, Linker, Module, Mutability, Store, Trap, Val,
    ValType,
};

static START: Once = Once::new();
const CONTRACT_MAIN: &str = "main";
const CONTRACT_DEPLOY: &str = "deploy";
const CONTRACT_HASH_TYPE: &str = "hash_type";
const BCOS_MODULE_NAME: &str = "bcos";
const BCOS_GLOBAL_GAS_VAR: &str = "gas";

static WASMTIME_ENGINE: Lazy<Engine> = Lazy::new(|| {
    let mut config = Config::new();
    config.async_support(true);
    // .cache_config_load_default()
    // .unwrap();
    match Engine::new(&config) {
        Ok(engine) => engine,
        Err(e) => {
            panic!("Failed to create wasmtime engine: {}", e);
        }
    }
});

static WASM_MODULE_CACHE: Lazy<Mutex<lru::LruCache<String, Module>>> = Lazy::new(|| {
    let mut capacity = 100;
    match env::var_os("BCOS_WASM_MODULE_CACHE_CAPACITY") {
        Some(val) => {
            info!("BCOS_WASM_MODULE_CACHE_CAPACITY is {}", capacity);
            capacity = val.into_string().unwrap().parse::<usize>().unwrap();
        }
        None => info!(
            "BCOS_WASM_MODULE_CACHE_CAPACITY not set, using default capacity {}",
            capacity
        ),
    };
    Mutex::new(LruCache::new(capacity))
});

static WASMTIME_LINKER: Lazy<Arc<Mutex<Linker<Arc<Mutex<EnvironmentInterface>>>>>> =
    Lazy::new(|| Arc::new(Mutex::new(Linker::new(&WASMTIME_ENGINE))));

#[derive(Debug, Clone)]
pub enum Error {
    OutOfGas(String),
    InvalidParameter(String),
    VMInternalError(String),
    InvalidReturnStatus(i32),
    Revert(String),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Error::OutOfGas(message) => write!(f, "out of gas, {}", message),
            Error::InvalidParameter(message) => write!(f, "InvalidParameter, {}", message),
            Error::VMInternalError(message) => write!(f, "VMInternalError, {}", message),
            Error::InvalidReturnStatus(code) => write!(f, "InvalidReturnStatus, {}", code),
            Error::Revert(message) => write!(f, "Revert, {}", message),
        }
    }
}

impl error::Error for Error {}

#[evmc_declare::evmc_declare_vm("bcos wasm", "fbwasm", "1.0.0-rc1")]
pub struct BcosWasm;

fn has_wasm_preamble(data: &[u8]) -> bool {
    data.len() >= 8 && data[0..4] == [0x00, 0x61, 0x73, 0x6d]
}

fn has_wasm_version(data: &[u8], version: u8) -> bool {
    data.len() >= 8 && data[4..8] == [version, 0x00, 0x00, 0x00]
}

fn init_linker_imports(linker: &mut Linker<Arc<Mutex<EnvironmentInterface>>>) {
    linker
        .func_wrap(
            BCOS_MODULE_NAME,
            "finish",
            |caller: Caller<'_, Arc<Mutex<EnvironmentInterface>>>,
             data_offset: u32,
             data_size: u32| {
                let env_interface = caller.data().clone();
                let mut env = env_interface.lock().unwrap();
                match env.finish(&caller, data_offset, data_size) {
                    Err(e) => {
                        return Err(Trap::new(format!("trap, {}", e)));
                    }
                    _ => Ok(()),
                }
            },
        )
        .unwrap()
        .func_wrap(
            BCOS_MODULE_NAME,
            "revert",
            |caller: Caller<'_, Arc<Mutex<EnvironmentInterface>>>,
             data_offset: u32,
             data_size: u32| {
                let env_interface = caller.data().clone();
                let mut env = env_interface.lock().unwrap();
                match env.revert(&caller, data_offset, data_size) {
                    Err(e) => {
                        return Err(Trap::new(format!("trap, {}", e)));
                    }
                    _ => Ok(()),
                }
            },
        )
        .unwrap()
        .func_wrap(
            BCOS_MODULE_NAME,
            "getAddress",
            |mut caller: Caller<'_, Arc<Mutex<EnvironmentInterface>>>, result_offset: u32| {
                let env_interface = caller.data().clone();
                let env = env_interface.lock().unwrap();
                match env.get_address(&mut caller, result_offset) {
                    Ok(len) => Ok(len),
                    Err(e) => {
                        return Err(Trap::new(format!("trap, {}", e)));
                    }
                }
            },
        )
        .unwrap()
        .func_wrap(
            BCOS_MODULE_NAME,
            "getCallDataSize",
            |caller: Caller<'_, Arc<Mutex<EnvironmentInterface>>>| {
                let env_interface = caller.data().clone();
                let env = env_interface.lock().unwrap();
                match env.get_call_data_size() {
                    Ok(len) => Ok(len),
                    Err(e) => {
                        return Err(Trap::new(format!("trap, {}", e)));
                    }
                }
            },
        )
        .unwrap()
        .func_wrap(
            BCOS_MODULE_NAME,
            "getCallData",
            |mut caller: Caller<'_, Arc<Mutex<EnvironmentInterface>>>, result_offset: u32| {
                let env_interface = caller.data().clone();
                let env = env_interface.lock().unwrap();
                match env.get_call_data(&mut caller, result_offset) {
                    Err(e) => {
                        return Err(Trap::new(format!("trap, {}", e)));
                    }
                    _ => Ok(()),
                }
            },
        )
        .unwrap()
        .func_wrap(
            BCOS_MODULE_NAME,
            "setStorage",
            |mut caller: Caller<'_, Arc<Mutex<EnvironmentInterface>>>,
             key_offset: u32,
             key_size: u32,
             value_offset: u32,
             value_size: u32| {
                let env_interface = caller.data().clone();
                let mut env = env_interface.lock().unwrap();
                match env.set_storage(&mut caller, key_offset, key_size, value_offset, value_size) {
                    Err(e) => {
                        return Err(Trap::new(format!("trap, {}", e)));
                    }
                    _ => Ok(()),
                }
            },
        )
        .unwrap()
        .func_wrap(
            BCOS_MODULE_NAME,
            "getStorage",
            |mut caller: Caller<'_, Arc<Mutex<EnvironmentInterface>>>,
             key_offset: u32,
             key_size: u32,
             value_offset: u32| {
                let value_size = 16 * 1024;
                let env_interface = caller.data().clone();
                let env = env_interface.lock().unwrap();
                match env.get_storage(&mut caller, key_offset, key_size, value_offset, value_size) {
                    Ok(len) => Ok(len),
                    Err(e) => {
                        return Err(Trap::new(format!("trap, {}", e)));
                    }
                }
            },
        )
        .unwrap()
        .func_wrap(
            BCOS_MODULE_NAME,
            "getCaller",
            |mut caller: Caller<'_, Arc<Mutex<EnvironmentInterface>>>, result_offset: u32| {
                let env_interface = caller.data().clone();
                let env = env_interface.lock().unwrap();
                match env.get_caller(&mut caller, result_offset) {
                    Ok(len) => Ok(len),
                    Err(e) => {
                        return Err(Trap::new(format!("trap, {}", e)));
                    }
                }
            },
        )
        .unwrap()
        .func_wrap(
            BCOS_MODULE_NAME,
            "getTxOrigin",
            |mut caller: Caller<'_, Arc<Mutex<EnvironmentInterface>>>, result_offset: u32| {
                let env_interface = caller.data().clone();
                let env = env_interface.lock().unwrap();
                match env.get_tx_origin(&mut caller, result_offset) {
                    Ok(len) => Ok(len),
                    Err(e) => {
                        return Err(Trap::new(format!("trap, {}", e)));
                    }
                }
            },
        )
        .unwrap()
        .func_wrap(
            BCOS_MODULE_NAME,
            "getExternalCodeSize",
            |mut caller: Caller<'_, Arc<Mutex<EnvironmentInterface>>>,
             address_offset: u32,
             size: u32| {
                let env_interface = caller.data().clone();
                let env = env_interface.lock().unwrap();
                match env.get_code_size(&mut caller, address_offset, size) {
                    Ok(len) => Ok(len),
                    Err(e) => {
                        return Err(Trap::new(format!("trap, {}", e)));
                    }
                }
            },
        )
        .unwrap()
        .func_wrap(
            BCOS_MODULE_NAME,
            "getBlockNumber",
            |caller: Caller<'_, Arc<Mutex<EnvironmentInterface>>>| -> i64 {
                let env_interface = caller.data();
                env_interface.lock().unwrap().get_block_number()
            },
        )
        .unwrap()
        .func_wrap(
            BCOS_MODULE_NAME,
            "getBlockTimestamp",
            |caller: Caller<'_, Arc<Mutex<EnvironmentInterface>>>| -> i64 {
                let env_interface = caller.data();
                env_interface.lock().unwrap().get_block_timestamp()
            },
        )
        .unwrap()
        .func_wrap(
            BCOS_MODULE_NAME,
            "log",
            |mut caller: Caller<'_, Arc<Mutex<EnvironmentInterface>>>,
             data_offset: u32,
             data_size: u32,
             number_of_topics: i32,
             topic1: u32,
             topic2: u32,
             topic3: u32,
             topic4: u32| {
                let env_interface = caller.data().clone();
                let mut env = env_interface.lock().unwrap();
                match env.log(
                    &mut caller,
                    data_offset,
                    data_size,
                    number_of_topics,
                    topic1,
                    topic2,
                    topic3,
                    topic4,
                ) {
                    Err(e) => {
                        return Err(Trap::new(format!("trap, {}", e)));
                    }
                    _ => Ok(()),
                }
            },
        )
        .unwrap()
        .func_wrap(
            BCOS_MODULE_NAME,
            "getReturnDataSize",
            |caller: Caller<'_, Arc<Mutex<EnvironmentInterface>>>| -> i32 {
                let env_interface = caller.data();
                env_interface.lock().unwrap().get_return_data_size()
            },
        )
        .unwrap()
        .func_wrap(
            BCOS_MODULE_NAME,
            "getReturnData",
            |mut caller: Caller<'_, Arc<Mutex<EnvironmentInterface>>>, result_offset: u32| {
                let env_interface = caller.data().clone();
                let env = env_interface.lock().unwrap();
                match env.get_return_data(&mut caller, result_offset) {
                    Err(e) => {
                        return Err(Trap::new(format!("trap, {}", e)));
                    }
                    _ => Ok(()),
                }
            },
        )
        .unwrap()
        .func_wrap(
            BCOS_MODULE_NAME,
            "call",
            |mut caller: Caller<'_, Arc<Mutex<EnvironmentInterface>>>,
             address_offset: u32,
             address_size: u32,
             data_offset: u32,
             data_size: u32| {
                let env_interface = caller.data().clone();
                let mut env = env_interface.lock().unwrap();
                match env.call(
                    &mut caller,
                    address_offset,
                    address_size,
                    data_offset,
                    data_size,
                ) {
                    Ok(status) => match status {
                        0 => Ok(0),
                        _ => Err(Trap::new("call failed")),
                    },
                    Err(e) => {
                        return Err(Trap::new(format!("trap, {}", e)));
                    }
                }
            },
        )
        .unwrap()
        .func_wrap(BCOS_MODULE_NAME, "outOfGas", || -> Result<(), Trap> {
            Err(Trap::new("Out Of Gas"))
        })
        .unwrap();
}

fn verify_contract(module: &Module) -> bool {
    if !module
        .exports()
        .any(|export| CONTRACT_MAIN.eq(export.name()))
    {
        error!("can't find contract {} function", CONTRACT_MAIN);
        return false;
    }
    if !module
        .exports()
        .any(|export| CONTRACT_DEPLOY.eq(export.name()))
    {
        error!("can't find contract {} function", CONTRACT_DEPLOY);
        return false;
    }
    // FIXME: check imports
    true
}

impl evmc_vm::EvmcVm for BcosWasm {
    fn init() -> Self {
        BcosWasm {}
    }
    fn execute<'a>(
        &self,
        _revision: evmc_vm::ffi::evmc_revision,
        code: &'a [u8],
        message: evmc_vm::ExecutionMessage,
        context: evmc_vm::ExecutionContext,
    ) -> evmc_vm::ExecutionResult {
        let mut start = Instant::now();
        START.call_once(|| {
            env_logger::init();
            {
                let mut linker = WASMTIME_LINKER.lock().unwrap();
                linker.allow_shadowing(true);
                init_linker_imports(&mut linker);
            }
            info!("wasm init");
        });
        if !has_wasm_preamble(code) {
            error!("Contract code is not valid wasm code");
            return evmc_vm::ExecutionResult::new(
                evmc_status_code::EVMC_CONTRACT_VALIDATION_FAILURE,
                0,
                0,
                None,
            );
        }
        if !has_wasm_version(code, 1) {
            error!("Contract has an invalid WebAssembly version {}", code[4]);
            return evmc_vm::ExecutionResult::new(
                evmc_status_code::EVMC_CONTRACT_VALIDATION_FAILURE,
                0,
                0,
                None,
            );
        }
        // get hash type from context
        let host_sm_crypto = context.get_host_context().isSMCrypto;
        let dest = String::from_utf8_lossy(message.destination()).to_string();
        if log_enabled!(Level::Info) {
            info!(
                "create runtime for {}, check code elapsed: {:?} μs",
                dest,
                start.elapsed().as_micros()
            );
            start = Instant::now();
        }
        let gas_limit = message.gas();
        let kind = message.kind();
        let env_interface = Arc::new(Mutex::new(EnvironmentInterface::new(context, message)));
        let module;
        {
            let mut modules = WASM_MODULE_CACHE.lock().unwrap();
            match modules.get(&dest) {
                Some(m) => {
                    if log_enabled!(Level::Debug) {
                        debug!("cached module hit for contract {}", dest);
                    }
                    module = m.clone();
                }
                None => {
                    module = match Module::from_binary(&WASMTIME_ENGINE, code) {
                        Ok(module) => {
                            if kind == evmc_call_kind::EVMC_CREATE && !verify_contract(&module) {
                                return evmc_vm::ExecutionResult::new(
                                    evmc_status_code::EVMC_CONTRACT_VALIDATION_FAILURE,
                                    0,
                                    0,
                                    None,
                                );
                            }
                            module
                        }
                        Err(e) => {
                            error!("Failed to compile wasm code to module: {}", e);
                            return evmc_vm::ExecutionResult::new(
                                evmc_status_code::EVMC_CONTRACT_VALIDATION_FAILURE,
                                0,
                                0,
                                None,
                            );
                        }
                    };
                }
            }
        }

        if log_enabled!(Level::Info) {
            info!(
                "Module::from_binary elapsed: {:?} μs",
                start.elapsed().as_micros()
            );
            start = Instant::now();
        }
        let mut store: Store<Arc<Mutex<EnvironmentInterface>>> =
            Store::new(&WASMTIME_ENGINE, env_interface.clone());
        // let mut linker: Linker<Arc<Mutex<EnvironmentInterface>>> = Linker::new(&WASMTIME_ENGINE);

        let ty = GlobalType::new(ValType::I64, Mutability::Var);
        let global_gas = Global::new(&mut store, ty, Val::I64(gas_limit)).unwrap();
        env_interface
            .lock()
            .unwrap()
            .set_gas_global(global_gas.clone());
        let instance;
        {
            let mut linker = WASMTIME_LINKER.lock().unwrap();
            linker
                .define(BCOS_MODULE_NAME, BCOS_GLOBAL_GAS_VAR, global_gas)
                .unwrap();
            if log_enabled!(Level::Info) {
                info!(
                    "prepare_imports elapsed: {:?} μs",
                    start.elapsed().as_micros()
                );
                start = Instant::now();
            }
            let instance_pre = match linker.instantiate_pre(&mut store, &module) {
                Ok(i) => i,
                Err(e) => {
                    error!("Failed to instantiate_pre wasmtime module: {}", e);
                    return evmc_vm::ExecutionResult::new(
                        evmc_status_code::EVMC_CONTRACT_VALIDATION_FAILURE,
                        0,
                        0,
                        None,
                    );
                }
            };
            instance = match task::block_on(instance_pre.instantiate_async(&mut store)) {
                Ok(instance) => instance,
                Err(e) => {
                    error!("Failed to instantiate wasmtime module: {}", e);
                    return evmc_vm::ExecutionResult::new(
                        evmc_status_code::EVMC_INTERNAL_ERROR,
                        0,
                        0,
                        None,
                    );
                }
            };
        }
        if log_enabled!(Level::Info) {
            info!(
                "instantiate wasm elapsed: {:?} μs",
                start.elapsed().as_micros()
            );
            start = Instant::now();
        }
        // extract memory from instance
        let memory = match instance.get_memory(&mut store, "memory") {
            Some(memory) => memory,
            _ => {
                error!("Failed to get memory from wasm module");
                return evmc_vm::ExecutionResult::new(
                    evmc_status_code::EVMC_CONTRACT_VALIDATION_FAILURE,
                    0,
                    0,
                    None,
                );
            }
        };
        env_interface.lock().unwrap().set_memory(memory.clone());

        let mut call_name = String::from(CONTRACT_MAIN);
        if kind == evmc_call_kind::EVMC_CREATE {
            call_name = String::from(CONTRACT_DEPLOY);
            if !verify_contract(&module) {
                error!("Contract code is not valid");
                return evmc_vm::ExecutionResult::new(
                    evmc_status_code::EVMC_CONTRACT_VALIDATION_FAILURE,
                    0,
                    0,
                    None,
                );
            }
            // call hash function of wasm module
            let func = match instance.get_typed_func::<(), i32, _>(&mut store, CONTRACT_HASH_TYPE) {
                Ok(func) => func,
                Err(e) => {
                    error!("Failed to get hash function: {}", e);
                    return evmc_vm::ExecutionResult::new(
                        evmc_status_code::EVMC_CONTRACT_VALIDATION_FAILURE,
                        0,
                        0,
                        None,
                    );
                }
            };
            // all wasm function need call_async because the coroutine
            let future = func.call_async(&mut store, ());
            let code_sm_crypto = match task::block_on(future) {
                Ok(ret) => match ret {
                    1 => true,
                    _ => false,
                },
                Err(e) => {
                    error!("Failed to call hash function: {}", e);
                    return evmc_vm::ExecutionResult::new(
                        evmc_status_code::EVMC_WASM_TRAP,
                        0,
                        0,
                        None,
                    );
                }
            };
            if host_sm_crypto != code_sm_crypto {
                error!(
                    "hash algorithm is not match, host use sm3: {}, contract use sm3: {}",
                    host_sm_crypto, code_sm_crypto
                );
                return evmc_vm::ExecutionResult::new(
                    evmc_status_code::EVMC_CONTRACT_VALIDATION_FAILURE,
                    0,
                    0,
                    None,
                );
            }
        }
        if log_enabled!(Level::Debug) {
            if kind == evmc_call_kind::EVMC_CREATE {
                debug!("check hash elapsed: {:?} μs", start.elapsed().as_micros());
                start = Instant::now();
            }
            debug!("call {} function", call_name);
        }
        // call hash function of wasm module
        let func = match instance.get_typed_func::<(), (), _>(&mut store, &call_name) {
            Ok(func) => func,
            Err(e) => {
                error!("Failed to get {} function: {}", call_name, e);
                return evmc_vm::ExecutionResult::new(
                    evmc_status_code::EVMC_CONTRACT_VALIDATION_FAILURE,
                    0,
                    0,
                    None,
                );
            }
        };
        let future = func.call_async(&mut store, ());
        match task::block_on(future) {
            Ok(ret) => ret,
            Err(e) => {
                error!("Failed to call {} function: {}", call_name, e);
                return evmc_vm::ExecutionResult::new(evmc_status_code::EVMC_WASM_TRAP, 0, 0, None);
            }
        };
        if log_enabled!(Level::Info) {
            info!(
                "call {} elapsed: {:?} μs",
                call_name,
                start.elapsed().as_micros()
            );
            start = Instant::now();
        }
        let env = env_interface.lock().unwrap();
        // get output from env_interface
        let output = env.get_output();
        let ret;
        if !env.reverted() {
            WASM_MODULE_CACHE.lock().unwrap().put(dest, module.clone());
            let gas_left = env.get_gas_left(&mut store).unwrap();
            if kind == evmc_call_kind::EVMC_CREATE {
                ret = evmc_vm::ExecutionResult::success(gas_left, 0, Some(code));
            } else {
                ret = evmc_vm::ExecutionResult::success(gas_left, 0, Some(output));
            }
        } else {
            ret = evmc_vm::ExecutionResult::new(evmc_status_code::EVMC_REVERT, 0, 0, Some(output));
        }
        if log_enabled!(Level::Debug) {
            debug!(
                "prepare result elapsed: {:?} μs",
                start.elapsed().as_micros()
            );
        }
        ret
    }
}
