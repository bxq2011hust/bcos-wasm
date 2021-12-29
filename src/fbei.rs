use evmc_vm::{
    Bytes32, ExecutionMessage, MessageFlags, MessageKind, StatusCode, StorageStatus, Uint256,
};
use sha3::Digest;
use std::cell::RefCell;
use std::{error, fmt};
use log::{debug};
use wasmtime::{AsContext, AsContextMut, Global, Memory, Val};

pub struct EnvironmentInterface<'a> {
    host_context: &'a mut evmc_vm::ExecutionContext<'a>,
    message: &'a evmc_vm::ExecutionMessage,
    gas_left: Option<RefCell<Global>>, // use RefCell to avoid mutable
    output: Vec<u8>,
    wasm_memory: Option<Memory>,
    revert: bool,
    last_call_return_data: Vec<u8>,
}

unsafe impl Send for EnvironmentInterface<'_> {}

unsafe impl Sync for EnvironmentInterface<'_> {}

// impl UnwindSafe for EnvironmentInterface<'_> {}

#[derive(Debug, Clone)]
pub enum ExecuteError {
    OutOfGas(String),
    InvalidParameter(String),
    VMInternalError(String),
    InvalidReturnStatus(i32),
}

impl fmt::Display for ExecuteError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            ExecuteError::OutOfGas(message) => write!(f, "out of gas, {}", message),
            // The wrapped error contains additional information and is available
            // via the source() method.
            ExecuteError::InvalidParameter(message) => write!(f, "InvalidParameter, {}", message),
            ExecuteError::VMInternalError(message) => write!(f, "VMInternalError, {}", message),
            ExecuteError::InvalidReturnStatus(code) => write!(f, "InvalidReturnStatus, {}", code),
        }
    }
}

impl error::Error for ExecuteError {}

fn wasm_memory_read(
    wasm_memory: &Memory,
    store: impl AsContext,
    offset: usize,
    buffer: &mut [u8],
    caller: &str,
) -> Result<(), ExecuteError> {
    match wasm_memory.read(&store, offset as usize, buffer) {
        Ok(_) => Ok(()),
        Err(_) => Err(ExecuteError::InvalidParameter(format!(
            "wasm_memory.read failed, caller: {}",
            caller
        ))),
    }
}

impl<'a> EnvironmentInterface<'a> {
    pub fn new(
        host_context: &'a mut evmc_vm::ExecutionContext<'a>,
        message: &'a evmc_vm::ExecutionMessage,
    ) -> Self {
        EnvironmentInterface {
            host_context,
            message,
            gas_left: None,
            output: Vec::new(),
            wasm_memory: None,
            revert: false,
            last_call_return_data: Vec::new(),
        }
    }
    pub fn set_memory(&mut self, memory: Memory) {
        self.wasm_memory = Some(memory);
    }
    pub fn set_gas_global(&mut self, gas: Global) {
        self.gas_left = Some(RefCell::new(gas));
    }
    pub fn get_gas_left(&self, mut store: impl AsContextMut) -> Result<i64, ExecuteError> {
        if let Some(gas_left) = &self.gas_left {
            match gas_left.borrow().get(&mut store).i64() {
                Some(gas) => Ok(gas),
                None => Err(ExecuteError::VMInternalError(
                    "gas_left.get() failed".to_string(),
                )),
            }
        } else {
            Err(ExecuteError::VMInternalError(String::from(
                "the global gas var is not init",
            )))
        }
    }
    pub fn get_output(&self) -> &[u8] {
        &self.output
    }

    fn read_wasm_memory(
        &self,
        store: impl AsContext,
        offset: usize,
        buffer: &mut [u8],
        caller: &str,
    ) -> Result<(), ExecuteError> {
        match &self.wasm_memory {
            Some(wasm_memory) => {
                wasm_memory_read(wasm_memory, &store, offset as usize, buffer, caller)
            }
            None => Err(ExecuteError::VMInternalError(format!(
                "{} failed, no wasm_memory",
                caller
            ))),
        }
    }
    fn write_wasm_memory(
        &self,
        mut store: impl AsContextMut,
        offset: usize,
        buffer: &[u8],
        caller: &str,
    ) -> Result<(), ExecuteError> {
        match &self.wasm_memory {
            Some(wasm_memory) => match wasm_memory.write(&mut store, offset as usize, buffer) {
                Ok(_) => Ok(()),
                Err(_) => Err(ExecuteError::InvalidParameter(format!(
                    "wasm_memory.write failed, caller: {}",
                    caller
                ))),
            },
            None => Err(ExecuteError::VMInternalError(format!(
                "{} failed, no wasm_memory",
                caller
            ))),
        }
    }
    fn take_gas(&self, mut store: impl AsContextMut, gas: i64) -> Result<(), ExecuteError> {
        if let Some(gas_left) = &self.gas_left {
            let remain = gas_left.borrow().get(&mut store).i64().unwrap() - gas;
            if remain < 0 {
                return Err(ExecuteError::OutOfGas(String::from("call takeGas")));
            }
            gas_left
                .borrow_mut()
                .set(&mut store, Val::I64(remain))
                .unwrap();
            return Ok(());
        } else {
            return Err(ExecuteError::VMInternalError(String::from(
                "the global gas var is not init",
            )));
        }
    }

    fn add_gas(&self, mut store: impl AsContextMut, gas: i64) -> Result<(), ExecuteError> {
        if let Some(gas_left) = &self.gas_left {
            let remain = gas_left.borrow().get(&mut store).i64().unwrap() + gas;
            if remain <= 0 {
                return Err(ExecuteError::OutOfGas(String::from("call add_gas")));
            }
            gas_left
                .borrow_mut()
                .set(&mut store, Val::I64(remain))
                .unwrap();
            return Ok(());
        } else {
            return Err(ExecuteError::VMInternalError(String::from(
                "the global gas var is not init",
            )));
        }
    }

    fn checksum_address(&self, bytes: &[u8; 20]) -> [u8; 40] {
        let mut result = [0u8; 40];
        let hex_address = hex::encode(bytes).to_lowercase();
        let hash;
        if (*self.host_context.get_host_context()).hash_fn.is_some() {
            hash = hex::encode(unsafe {
                (*self.host_context.get_host_context()).hash_fn.unwrap()(
                    hex_address.as_bytes().as_ptr(),
                    hex_address.as_bytes().len(),
                )
                .bytes
            });
        } else {
            // let mut hasher = sha3::Keccak256::default();
            hash = hex::encode(sha3::Keccak256::digest(hex_address.as_bytes()));
        }
        for (i, c) in hex_address.as_str().char_indices() {
            let v = u16::from_str_radix(&hash[i..i + 1], 16).unwrap();
            if v >= 8 {
                result[i] = c.to_uppercase().next().unwrap() as u8;
            } else {
                result[i] = c as u8;
            }
        }
        result
    }
    // pub fn use_gas(&mut self, gas: i64){
    //     println!("use_gas: {}", gas);
    // }
    pub fn finish(
        &mut self,
        store: impl AsContext,
        data_offset: u32,
        data_size: u32,
    ) -> Result<(), ExecuteError> {
        self.revert = false;
        self.output.resize(data_size as usize, 0);
        let buffer = self.output.as_mut_slice();
        let caller = "finish";
        match &self.wasm_memory {
            Some(wasm_memory) => {
                wasm_memory_read(wasm_memory, &store, data_offset as usize, buffer, caller)
            }
            None => Err(ExecuteError::VMInternalError(format!(
                "{} failed, no wasm_memory",
                caller
            ))),
        }
    }
    pub fn revert(
        &mut self,
        store: impl AsContext,
        data_offset: u32,
        data_size: u32,
    ) -> Result<(), ExecuteError> {
        self.revert = true;
        self.output.resize(data_size as usize, 0);
        let buffer = self.output.as_mut_slice();
        let caller = "revert";
        match &self.wasm_memory {
            Some(wasm_memory) => {
                wasm_memory_read(wasm_memory, &store, data_offset as usize, buffer, caller)
            }
            None => Err(ExecuteError::VMInternalError(format!(
                "{} failed, no wasm_memory",
                caller
            ))),
        }
    }
    pub fn reverted(&self) -> bool {
        self.revert
    }
    // get the address of the current contract
    pub fn get_address(
        &self,
        mut store: impl AsContextMut,
        result_offset: u32,
    ) -> Result<i32, ExecuteError> {
        self.write_wasm_memory(
            &mut store,
            result_offset as usize,
            self.message.destination().as_slice(),
            "get_address",
        )?;
        Ok(self.message.destination().len() as i32)
    }
    pub fn get_call_data_size(&self) -> Result<i32, ExecuteError> {
        match self.message.input() {
            Some(input) => Ok(input.len() as i32),
            None => Ok(0),
        }
    }
    pub fn get_call_data(
        &self,
        mut store: impl AsContextMut,
        result_offset: u32,
    ) -> Result<(), ExecuteError> {
        match self.message.input() {
            Some(input) => self.write_wasm_memory(
                &mut store,
                result_offset as usize,
                input.as_slice(),
                "get_call_data",
            ),
            None => {
                debug!("call get_call_data without input");
                Ok(())
            }
        }
    }
    // fn create(&mut self, data_offset: u32, size : u32, result_offset: u32)-> Result<i32, ExecuteError>;
    pub fn set_storage(
        &mut self,
        store: impl AsContext,
        key_offset: u32,
        key_size: u32,
        value_offset: u32,
        value_size: u32,
    ) -> Result<StorageStatus, ExecuteError> {
        let mut key = vec![0u8; key_size as usize];
        let mut value: Vec<u8> = vec![0u8; value_size as usize];
        self.read_wasm_memory(
            &store,
            key_offset as usize,
            key.as_mut_slice(),
            "set_storage",
        )?;
        self.read_wasm_memory(
            &store,
            value_offset as usize,
            value.as_mut_slice(),
            "set_storage",
        )?;
        Ok(self.host_context.wasm_set_storage(
            self.message.destination().as_slice(),
            key.as_slice(),
            value.as_slice(),
        ))
    }
    pub fn get_storage(
        &self,
        mut store: impl AsContextMut,
        key_offset: u32,
        key_size: u32,
        value_offset: u32,
        value_size: u32,
    ) -> Result<i32, ExecuteError> {
        let mut key = vec![0u8; key_size as usize];
        let mut value: Vec<u8> = vec![0u8; value_size as usize];
        self.read_wasm_memory(
            &store,
            key_offset as usize,
            key.as_mut_slice(),
            "get_storage",
        )?;
        let value_len = self.host_context.wasm_get_storage(
            self.message.destination().as_slice(),
            key.as_slice(),
            value.as_mut_slice(),
        );
        value.resize(value_len as usize, 0);
        match self.write_wasm_memory(
            &mut store,
            value_offset as usize,
            value.as_mut_slice(),
            "get_storage",
        ) {
            Ok(()) => Ok(value_len),
            Err(e) => Err(e),
        }
    }
    pub fn get_caller(
        &self,
        mut store: impl AsContextMut,
        result_offset: u32,
    ) -> Result<i32, ExecuteError> {
        println!("get_caller: {}", result_offset);
        if self.host_context.get_tx_context().tx_origin.bytes == self.message.sender().as_slice() {
            // if caller is account return eip-55 address else return string
            self.get_tx_origin(&mut store, result_offset)
        } else {
            self.write_wasm_memory(
                &mut store,
                result_offset as usize,
                self.message.sender().as_slice(),
                "get_caller",
            )?;
            Ok(self.message.sender().len() as i32)
        }
    }
    pub fn get_tx_origin(
        &self,
        mut store: impl AsContextMut,
        result_offset: u32,
    ) -> Result<i32, ExecuteError> {
        // the return is always 40 bytes
        let checksum_address =
            self.checksum_address(&self.host_context.get_tx_context().tx_origin.bytes);
        self.write_wasm_memory(
            &mut store,
            result_offset as usize,
            &checksum_address,
            "get_return_data",
        )?;
        Ok(checksum_address.len() as i32)
    }
    pub fn get_code_size(
        &self,
        store: impl AsContext,
        address_offset: u32,
        size: u32,
    ) -> Result<i32, ExecuteError> {
        let mut address = vec![0u8; size as usize];
        self.read_wasm_memory(
            &store,
            address_offset as usize,
            address.as_mut_slice(),
            "get_code_size",
        )?;
        Ok(self.host_context.wasm_get_code_size(address.as_slice()) as i32)
    }
    pub fn get_block_number(&self) -> i64 {
        self.host_context.get_tx_context().block_number
    }
    pub fn get_block_timestamp(&self) -> i64 {
        self.host_context.get_tx_context().block_timestamp
    }
    pub fn log(
        &mut self,
        store: impl AsContext,
        data_offset: u32,
        data_size: u32,
        number_of_topics: i32,
        topic1: u32,
        topic2: u32,
        topic3: u32,
        topic4: u32,
    ) -> Result<(), ExecuteError> {
        let mut data = vec![0u8; data_size as usize];
        let mut topics: Vec<Bytes32> = vec![Bytes32::default(); number_of_topics as usize];
        self.read_wasm_memory(&store, data_offset as usize, data.as_mut_slice(), "log")?;
        for i in 0..number_of_topics {
            self.read_wasm_memory(
                &store,
                match i {
                    0 => topic1,
                    1 => topic2,
                    2 => topic3,
                    3 => topic4,
                    _ => 0,
                } as usize,
                topics[i as usize].bytes.as_mut(),
                "log",
            )?;
        }
        Ok(self.host_context.wasm_emit_log(
            self.message.destination().as_slice(),
            data.as_slice(),
            topics.as_slice(),
        ))
    }
    pub fn get_return_data_size(&self) -> i32 {
        self.last_call_return_data.len() as i32
    }
    pub fn get_return_data(
        &self,
        mut store: impl AsContextMut,
        result_offset: u32,
    ) -> Result<(), ExecuteError> {
        self.write_wasm_memory(
            &mut store,
            result_offset as usize,
            self.last_call_return_data.as_slice(),
            "get_return_data",
        )
    }
    pub fn call(
        &mut self,
        mut store: impl AsContextMut,
        address_offset: u32,
        address_size: u32,
        data_offset: u32,
        data_size: u32,
    ) -> Result<i32, ExecuteError> {
        let gas_left = self.get_gas_left(&mut store)?;
        let mut address: Vec<u8> = vec![0u8; address_size as usize];
        self.read_wasm_memory(
            &store,
            address_offset as usize,
            address.as_mut_slice(),
            "call",
        )?;
        let mut calldata: Vec<u8> = vec![0u8; data_size as usize];
        self.read_wasm_memory(
            &store,
            data_offset as usize,
            calldata.as_mut_slice(),
            "call",
        )?;
        let flags = self.message.flags() & MessageFlags::EVMC_STATIC as u32;
        let message = ExecutionMessage::new(
            MessageKind::EVMC_CALL,
            flags,
            self.message.depth() + 1,
            gas_left,
            address,
            self.message.destination().clone(),
            {
                if data_size > 0 {
                    Some(calldata)
                } else {
                    None
                }
            },
            Uint256 { bytes: [0u8; 32] },
            Bytes32::default(),
        );
        self.take_gas(&mut store, gas_left)?;
        let result = self.host_context.call(&message);
        match result.output() {
            Some(output) => {
                self.last_call_return_data = output.clone();
            }
            None => {
                self.last_call_return_data.clear();
            }
        };
        // return gas
        let unused_gas = result.gas_left();
        self.add_gas(&mut store, unused_gas)?;
        // check status
        match result.status_code() {
            StatusCode::EVMC_SUCCESS => Ok(0),
            StatusCode::EVMC_REVERT => Ok(2),
            StatusCode::EVMC_FAILURE => Ok(1),
            _ => Err(ExecuteError::InvalidReturnStatus(
                result.status_code() as i32
            )),
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;
    fn checksum_address(bytes: &[u8]) -> [u8; 40] {
        let mut result = [0u8; 40];
        let hex_address = hex::encode(bytes).to_lowercase();
        let hash = hex::encode(sha3::Keccak256::digest(hex_address.as_bytes()));
        for (i, c) in hex_address.as_str().char_indices() {
            let v = u16::from_str_radix(&hash[i..i + 1], 16).unwrap();
            if v >= 8 {
                result[i] = c.to_uppercase().next().unwrap() as u8;
            } else {
                result[i] = c as u8;
            }
        }
        result
    }
    #[test]
    fn check_sum_works() {
        assert_eq!(
            checksum_address(
                hex::decode("5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed")
                    .unwrap()
                    .as_slice()
            ),
            "5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed".as_bytes()
        );
        assert_eq!(
            checksum_address(
                hex::decode("fB6916095ca1df60bB79Ce92cE3Ea74c37c5d359")
                    .unwrap()
                    .as_slice()
            ),
            "fB6916095ca1df60bB79Ce92cE3Ea74c37c5d359".as_bytes()
        );
        assert_eq!(
            checksum_address(
                hex::decode("dbF03B407c01E7cD3CBea99509d93f8DDDC8C6FB")
                    .unwrap()
                    .as_slice()
            ),
            "dbF03B407c01E7cD3CBea99509d93f8DDDC8C6FB".as_bytes()
        );
        assert_eq!(
            checksum_address(
                hex::decode("D1220A0cf47c7B9Be7A2E6BA89F429762e7b9aDb")
                    .unwrap()
                    .as_slice()
            ),
            "D1220A0cf47c7B9Be7A2E6BA89F429762e7b9aDb".as_bytes()
        );
    }
}
