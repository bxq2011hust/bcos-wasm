use evmc_vm::ffi::{evmc_call_kind, evmc_status_code};
use futures::executor::block_on;
use std::sync::Once;
// use log::{debug, error, info, log_enabled, Level};
use std::sync::{Arc, Mutex};
use wasmtime::{
    Caller, Config, Engine, Global, GlobalType, Linker, Module, Mutability, Store, Trap, Val,
    ValType,
};

mod fbei;
use fbei::EnvironmentInterface;
use lazy_static::lazy_static;
use log::{debug, error, info, log_enabled, Level};

static START: Once = Once::new();
lazy_static! {
    static ref WASMTIME_ENGINE: Engine = {
        let mut config = Config::new();
        config
            .async_support(true)
            .cache_config_load_default()
            .unwrap();
        match Engine::new(&config) {
            Ok(engine) => engine,
            Err(e) => {
                panic!("Failed to create wasmtime engine: {}", e);
            }
        }
    };
}
#[evmc_declare::evmc_declare_vm("fbwasm", "fbwasm", "1.0.0-rc1")]
pub struct FbWasm;

const BCOS_MODULE_NAME: &str = "bcos";
const BCOS_GLOBAL_GAS_VAR: &str = "gas";

fn has_wasm_preamble(data: &[u8]) -> bool {
    data.len() >= 8 && data[0..4] == [0x00, 0x61, 0x73, 0x6d]
}

fn has_wasm_version(data: &[u8], version: u8) -> bool {
    data.len() >= 8 && data[4..8] == [0x01, 0x00, 0x00, 0x00] && data[8..12] == [version, 0, 0, 0]
}

fn prepare_imports(linker: &mut Linker<Arc<Mutex<EnvironmentInterface>>>) {
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
                let env = caller.data().lock().unwrap();
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
            |caller: Caller<'_, Arc<Mutex<EnvironmentInterface>>>,
             key_offset: u32,
             key_size: u32,
             value_offset: u32,
             value_size: u32| {
                let env_interface = caller.data().clone();
                let mut env = env_interface.lock().unwrap();
                match env.set_storage(&caller, key_offset, key_size, value_offset, value_size) {
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
             value_offset: u32,
             value_size: u32| {
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
            |caller: Caller<'_, Arc<Mutex<EnvironmentInterface>>>,
             address_offset: u32,
             size: u32| {
                let env_interface = caller.data().clone();
                let env = env_interface.lock().unwrap();
                match env.get_code_size(&caller, address_offset, size) {
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
        .unwrap();
}

fn verify_contract(module: &Module) -> bool {
    // TODO: add logic of verify contract
    true
}

impl evmc_vm::EvmcVm for FbWasm {
    fn init() -> Self {
        FbWasm {}
    }
    fn execute<'a>(
        &self,
        _revision: evmc_vm::ffi::evmc_revision,
        code: &'a [u8],
        message: &'a evmc_vm::ExecutionMessage,
        context: Option<&'a mut evmc_vm::ExecutionContext<'a>>,
    ) -> evmc_vm::ExecutionResult {
        START.call_once(|| {
            info!("fbwasm start");
            env_logger::init();
        });
        let context = match context {
            Some(c) => c,
            None => {
                return evmc_vm::ExecutionResult::new(
                    evmc_status_code::EVMC_INTERNAL_ERROR,
                    0,
                    None,
                );
            }
        };
        if !has_wasm_preamble(code) {
            error!("Contract code is not valid wasm code");
            return evmc_vm::ExecutionResult::new(
                evmc_status_code::EVMC_CONTRACT_VALIDATION_FAILURE,
                0,
                None,
            );
        }
        if !has_wasm_version(code, 1) {
            error!("Contract has an invalid WebAssembly version");
            return evmc_vm::ExecutionResult::new(
                evmc_status_code::EVMC_CONTRACT_VALIDATION_FAILURE,
                0,
                None,
            );
        }
        // get hash type from context
        let host_sm_crypto = context.get_host_context().isSMCrypto;
        debug!("Create wasmtime runtime to run contract");
        //let my_address = message.destination();

        let env_interface = Arc::new(Mutex::new(EnvironmentInterface::new(context, message)));
        // let mut config = Config::new();
        // config
        //     .async_support(true)
        //     .cache_config_load_default()
        //     .unwrap();
        // let engine = match Engine::new(&WASMTIME_CONFIG) {
        //     Ok(engine) => engine,
        //     Err(e) => {
        //         error!("Failed to create wasmtime engine: {}", e);
        //         return evmc_vm::ExecutionResult::new(
        //             evmc_status_code::EVMC_CONTRACT_VALIDATION_FAILURE,
        //             0,
        //             None,
        //         );
        //     }
        // };
        let module = match Module::from_binary(&WASMTIME_ENGINE, code) {
            Ok(module) => module,
            Err(e) => {
                error!("Failed to create wasmtime engine: {}", e);
                return evmc_vm::ExecutionResult::new(
                    evmc_status_code::EVMC_CONTRACT_VALIDATION_FAILURE,
                    0,
                    None,
                );
            }
        };
        let mut store: Store<Arc<Mutex<EnvironmentInterface>>> =
            Store::new(&WASMTIME_ENGINE, env_interface.clone());
        // let store_context = store.as_context_mut();
        let mut linker: Linker<Arc<Mutex<EnvironmentInterface>>> = Linker::new(&WASMTIME_ENGINE);
        let ty = GlobalType::new(ValType::I64, Mutability::Var);
        let global_gas = Global::new(&mut store, ty, Val::I64(message.gas())).unwrap();
        env_interface
            .lock()
            .unwrap()
            .set_gas_global(global_gas.clone());
        prepare_imports(&mut linker);
        // TODO: because the global owned by store is defined, the linker can not used to instantiate many modules
        linker
            .define(BCOS_MODULE_NAME, BCOS_GLOBAL_GAS_VAR, global_gas)
            .unwrap();
        let instance = match linker.instantiate(&mut store, &module) {
            Ok(instance) => instance,
            Err(e) => {
                error!("Failed to instantiate wasmtime module: {}", e);
                return evmc_vm::ExecutionResult::new(
                    evmc_status_code::EVMC_CONTRACT_VALIDATION_FAILURE,
                    0,
                    None,
                );
            }
        };
        // extract memory from instance
        let memory = match instance.get_memory(&mut store, "memory") {
            Some(memory) => memory,
            _ => {
                error!("Failed to get memory from wasmt module");
                return evmc_vm::ExecutionResult::new(
                    evmc_status_code::EVMC_CONTRACT_VALIDATION_FAILURE,
                    0,
                    None,
                );
            }
        };
        env_interface.lock().unwrap().set_memory(memory.clone());

        if message.kind() == evmc_call_kind::EVMC_CREATE {
            debug!("verify contract");
            if !verify_contract(&module) {
                error!("Contract code is not valid");
                return evmc_vm::ExecutionResult::new(
                    evmc_status_code::EVMC_CONTRACT_VALIDATION_FAILURE,
                    0,
                    None,
                );
            }
        }
        let mut call_name = String::from("main");
        if message.kind() == evmc_call_kind::EVMC_CREATE {
            call_name = String::from("deploy");

            // call hash function of wasm module
            let func = match instance.get_typed_func::<(), i32, _>(&mut store, "hash") {
                Ok(func) => func,
                Err(e) => {
                    error!("Failed to get hash function: {}", e);
                    return evmc_vm::ExecutionResult::new(
                        evmc_status_code::EVMC_CONTRACT_VALIDATION_FAILURE,
                        0,
                        None,
                    );
                }
            };
            // all wasm function need call_async because the coroutine
            let future = func.call_async(&mut store, ());
            let code_sm_crypto = match block_on(future) {
                Ok(ret) => match ret {
                    1 => true,
                    _ => false,
                },
                Err(e) => {
                    error!("Failed to call hash function: {}", e);
                    return evmc_vm::ExecutionResult::new(
                        evmc_status_code::EVMC_WASM_TRAP,
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
                    None,
                );
            }
        }
        if log_enabled!(log::Level::Debug) {
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
                    None,
                );
            }
        };
        let future = func.call_async(&mut store, ());
        match block_on(future) {
            Ok(ret) => ret,
            Err(e) => {
                error!("Failed to call {} function: {}", call_name, e);
                return evmc_vm::ExecutionResult::new(evmc_status_code::EVMC_WASM_TRAP, 0, None);
            }
        };
        // get gas left from env_interface
        let env = env_interface.lock().unwrap();
        // get output from env_interface
        let output = env.get_output();
        if !env.reverted() {
            let gas_left = env.get_gas_left(&mut store).unwrap();
            if message.kind() == evmc_call_kind::EVMC_CREATE {
                evmc_vm::ExecutionResult::success(gas_left, Some(code))
            } else {
                evmc_vm::ExecutionResult::success(gas_left, Some(output))
            }
        } else {
            evmc_vm::ExecutionResult::new(evmc_status_code::EVMC_REVERT, 0, Some(output))
        }
    }
}
