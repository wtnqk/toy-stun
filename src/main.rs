use std::net::{UdpSocket, SocketAddr};

const MAGIC_COOKIE: u32 = 0x2112A442;

const BINDING_REQUEST: u16 = 0x0001;
const BINDING_SUCCESS_RESPONSE: u16 = 0x0101;

const ATTR_XOR_MAPPED_ADDRESS: u16 = 0x0020;

#[derive(Debug, Clone, PartialEq)]
struct StunHeader {
    message_type: u16,
    message_length: u16,
    magic_cookie: u32,
    transaction_id: [u8; 12],
}

#[derive(Debug, Clone, PartialEq)]
struct StunAttribute {
    attr_type: u16,
    length: u16,
    value: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq)]
struct StunMessage {
    header: StunHeader,
    attributes: Vec<StunAttribute>,
}

fn handle_stun_request(data: &[u8], src_addr: SocketAddr) -> Result<Vec<u8>, &'static str> {
    let request = StunMessage::from_bytes(data)?;
    
    // Verify it's a binding request
    if request.header.message_type != BINDING_REQUEST {
        return Err("Not a binding request");
    }
    
    // Verify magic cookie
    if request.header.magic_cookie != MAGIC_COOKIE {
        return Err("Invalid magic cookie");
    }
    
    // Create response
    let mut response = StunMessage {
        header: StunHeader {
            message_type: BINDING_SUCCESS_RESPONSE,
            message_length: 0,
            magic_cookie: MAGIC_COOKIE,
            transaction_id: request.header.transaction_id,
        },
        attributes: vec![],
    };
    
    // Add XOR-MAPPED-ADDRESS attribute
    match src_addr {
        SocketAddr::V4(addr) => {
            let ip_bytes = addr.ip().octets();
            let port = addr.port();
            let attr = create_xor_mapped_address_ipv4(ip_bytes, port, &request.header.transaction_id);
            response.attributes.push(attr);
        }
        SocketAddr::V6(_) => {
            return Err("IPv6 not supported yet");
        }
    }
    
    response.update_message_length();
    Ok(response.to_bytes())
}

fn main() {
    let bind_addr = "0.0.0.0:3478";
    let socket = match UdpSocket::bind(bind_addr) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("Failed to bind to {}: {}", bind_addr, e);
            return;
        }
    };
    
    println!("STUN Server listening on {}", bind_addr);
    
    let mut buffer = [0u8; 1500];
    
    loop {
        match socket.recv_from(&mut buffer) {
            Ok((size, src_addr)) => {
                println!("Received {} bytes from {}", size, src_addr);
                
                match handle_stun_request(&buffer[..size], src_addr) {
                    Ok(response) => {
                        match socket.send_to(&response, src_addr) {
                            Ok(sent) => {
                                println!("Sent {} bytes response to {}", sent, src_addr);
                            }
                            Err(e) => {
                                eprintln!("Failed to send response: {}", e);
                            }
                        }
                    }
                    Err(e) => {
                        eprintln!("Failed to handle request: {}", e);
                    }
                }
            }
            Err(e) => {
                eprintln!("Failed to receive data: {}", e);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_stun_header_creation() {
        let transaction_id = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12];
        let header = StunHeader {
            message_type: BINDING_REQUEST,
            message_length: 0,
            magic_cookie: MAGIC_COOKIE,
            transaction_id,
        };

        assert_eq!(header.message_type, BINDING_REQUEST);
        assert_eq!(header.message_length, 0);
        assert_eq!(header.magic_cookie, MAGIC_COOKIE);
        assert_eq!(header.transaction_id, transaction_id);
    }

    #[test]
    fn test_stun_attribute_creation() {
        let value = vec![192, 168, 1, 1];
        let attr = StunAttribute {
            attr_type: ATTR_XOR_MAPPED_ADDRESS,
            length: value.len() as u16,
            value: value.clone(),
        };

        assert_eq!(attr.attr_type, ATTR_XOR_MAPPED_ADDRESS);
        assert_eq!(attr.length, 4);
        assert_eq!(attr.value, value);
    }

    #[test]
    fn test_stun_message_creation() {
        let transaction_id = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12];
        let header = StunHeader {
            message_type: BINDING_REQUEST,
            message_length: 0,
            magic_cookie: MAGIC_COOKIE,
            transaction_id,
        };

        let message = StunMessage {
            header,
            attributes: vec![],
        };

        assert_eq!(message.header.message_type, BINDING_REQUEST);
        assert_eq!(message.attributes.len(), 0);
    }

    #[test]
    fn test_stun_header_serialization() {
        let transaction_id = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12];
        let header = StunHeader {
            message_type: BINDING_REQUEST,
            message_length: 0,
            magic_cookie: MAGIC_COOKIE,
            transaction_id,
        };

        let bytes = header.to_bytes();
        assert_eq!(bytes.len(), 20);
        assert_eq!(&bytes[0..2], &[0x00, 0x01]); // BINDING_REQUEST
        assert_eq!(&bytes[2..4], &[0x00, 0x00]); // message_length
        assert_eq!(&bytes[4..8], &MAGIC_COOKIE.to_be_bytes());
        assert_eq!(&bytes[8..20], &transaction_id);
    }

    #[test]
    fn test_stun_header_parsing() {
        let mut bytes = vec![0; 20];
        bytes[0..2].copy_from_slice(&BINDING_REQUEST.to_be_bytes());
        bytes[2..4].copy_from_slice(&12u16.to_be_bytes());
        bytes[4..8].copy_from_slice(&MAGIC_COOKIE.to_be_bytes());
        let transaction_id = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12];
        bytes[8..20].copy_from_slice(&transaction_id);

        let header = StunHeader::from_bytes(&bytes).unwrap();
        assert_eq!(header.message_type, BINDING_REQUEST);
        assert_eq!(header.message_length, 12);
        assert_eq!(header.magic_cookie, MAGIC_COOKIE);
        assert_eq!(header.transaction_id, transaction_id);
    }

    #[test]
    fn test_stun_attribute_serialization() {
        let value = vec![0x00, 0x01, 0xc0, 0xa8, 0x01, 0x01];
        let attr = StunAttribute {
            attr_type: ATTR_XOR_MAPPED_ADDRESS,
            length: value.len() as u16,
            value: value.clone(),
        };

        let bytes = attr.to_bytes();
        assert_eq!(&bytes[0..2], &ATTR_XOR_MAPPED_ADDRESS.to_be_bytes());
        assert_eq!(&bytes[2..4], &6u16.to_be_bytes());
        assert_eq!(&bytes[4..10], &value[..]);
        // Check padding
        assert_eq!(bytes.len(), 12); // 4 (header) + 6 (value) + 2 (padding)
    }

    #[test]
    fn test_xor_mapped_address_ipv4() {
        let ip = [192, 168, 1, 1];
        let port = 12345u16;
        let transaction_id = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12];

        let attr = create_xor_mapped_address_ipv4(ip, port, &transaction_id);
        
        assert_eq!(attr.attr_type, ATTR_XOR_MAPPED_ADDRESS);
        assert_eq!(attr.length, 8);
        
        // Verify family
        assert_eq!(attr.value[1], 0x01); // IPv4
        
        // Verify XOR'd port
        let xor_port = u16::from_be_bytes([attr.value[2], attr.value[3]]);
        let expected_port = port ^ (MAGIC_COOKIE >> 16) as u16;
        assert_eq!(xor_port, expected_port);
        
        // Verify XOR'd IP
        let xor_ip = &attr.value[4..8];
        let magic_bytes = MAGIC_COOKIE.to_be_bytes();
        for i in 0..4 {
            assert_eq!(xor_ip[i], ip[i] ^ magic_bytes[i]);
        }
    }

    #[test]
    fn test_stun_message_roundtrip() {
        let transaction_id = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12];
        let mut message = StunMessage {
            header: StunHeader {
                message_type: BINDING_SUCCESS_RESPONSE,
                message_length: 0,
                magic_cookie: MAGIC_COOKIE,
                transaction_id,
            },
            attributes: vec![],
        };

        let attr = create_xor_mapped_address_ipv4([192, 168, 1, 1], 12345, &transaction_id);
        message.attributes.push(attr);
        message.update_message_length();

        let bytes = message.to_bytes();
        let parsed = StunMessage::from_bytes(&bytes).unwrap();
        
        assert_eq!(parsed.header.message_type, BINDING_SUCCESS_RESPONSE);
        assert_eq!(parsed.attributes.len(), 1);
        assert_eq!(parsed.attributes[0].attr_type, ATTR_XOR_MAPPED_ADDRESS);
    }

    #[test]
    fn test_handle_binding_request() {
        use std::net::{IpAddr, Ipv4Addr};
        
        let transaction_id = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12];
        let request = StunMessage {
            header: StunHeader {
                message_type: BINDING_REQUEST,
                message_length: 0,
                magic_cookie: MAGIC_COOKIE,
                transaction_id,
            },
            attributes: vec![],
        };
        
        let request_bytes = request.to_bytes();
        let src_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100)), 5678);
        
        let response_bytes = handle_stun_request(&request_bytes, src_addr).unwrap();
        let response = StunMessage::from_bytes(&response_bytes).unwrap();
        
        // Check response header
        assert_eq!(response.header.message_type, BINDING_SUCCESS_RESPONSE);
        assert_eq!(response.header.transaction_id, transaction_id);
        assert_eq!(response.header.magic_cookie, MAGIC_COOKIE);
        
        // Check XOR-MAPPED-ADDRESS attribute
        assert_eq!(response.attributes.len(), 1);
        assert_eq!(response.attributes[0].attr_type, ATTR_XOR_MAPPED_ADDRESS);
        
        // Verify the XOR-MAPPED-ADDRESS contains correct data
        let attr = &response.attributes[0];
        assert_eq!(attr.value[1], 0x01); // IPv4 family
        
        // Decode XOR'd port
        let xor_port = u16::from_be_bytes([attr.value[2], attr.value[3]]);
        let actual_port = xor_port ^ (MAGIC_COOKIE >> 16) as u16;
        assert_eq!(actual_port, 5678);
        
        // Decode XOR'd IP
        let magic_bytes = MAGIC_COOKIE.to_be_bytes();
        let mut actual_ip = [0u8; 4];
        for i in 0..4 {
            actual_ip[i] = attr.value[4 + i] ^ magic_bytes[i];
        }
        assert_eq!(actual_ip, [192, 168, 1, 100]);
    }

    #[test]
    fn test_handle_invalid_message_type() {
        use std::net::{IpAddr, Ipv4Addr};
        
        let request = StunMessage {
            header: StunHeader {
                message_type: 0x0002, // Not a binding request
                message_length: 0,
                magic_cookie: MAGIC_COOKIE,
                transaction_id: [0; 12],
            },
            attributes: vec![],
        };
        
        let request_bytes = request.to_bytes();
        let src_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100)), 5678);
        
        let result = handle_stun_request(&request_bytes, src_addr);
        assert!(result.is_err());
        assert_eq!(result.err().unwrap(), "Not a binding request");
    }

    #[test]
    fn test_handle_invalid_magic_cookie() {
        use std::net::{IpAddr, Ipv4Addr};
        
        let request = StunMessage {
            header: StunHeader {
                message_type: BINDING_REQUEST,
                message_length: 0,
                magic_cookie: 0x12345678, // Wrong magic cookie
                transaction_id: [0; 12],
            },
            attributes: vec![],
        };
        
        let request_bytes = request.to_bytes();
        let src_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100)), 5678);
        
        let result = handle_stun_request(&request_bytes, src_addr);
        assert!(result.is_err());
        assert_eq!(result.err().unwrap(), "Invalid magic cookie");
    }
}

impl StunHeader {
    fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(20);
        bytes.extend_from_slice(&self.message_type.to_be_bytes());
        bytes.extend_from_slice(&self.message_length.to_be_bytes());
        bytes.extend_from_slice(&self.magic_cookie.to_be_bytes());
        bytes.extend_from_slice(&self.transaction_id);
        bytes
    }

    fn from_bytes(bytes: &[u8]) -> Result<Self, &'static str> {
        if bytes.len() < 20 {
            return Err("STUN header must be at least 20 bytes");
        }

        let message_type = u16::from_be_bytes([bytes[0], bytes[1]]);
        let message_length = u16::from_be_bytes([bytes[2], bytes[3]]);
        let magic_cookie = u32::from_be_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]);
        
        let mut transaction_id = [0u8; 12];
        transaction_id.copy_from_slice(&bytes[8..20]);

        Ok(StunHeader {
            message_type,
            message_length,
            magic_cookie,
            transaction_id,
        })
    }
}

impl StunAttribute {
    fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&self.attr_type.to_be_bytes());
        bytes.extend_from_slice(&self.length.to_be_bytes());
        bytes.extend_from_slice(&self.value);
        
        // STUN attributes must be padded to 4-byte boundaries
        let padding = (4 - (self.value.len() % 4)) % 4;
        bytes.extend_from_slice(&vec![0u8; padding]);
        
        bytes
    }
}

impl StunMessage {
    fn update_message_length(&mut self) {
        let mut length = 0;
        for attr in &self.attributes {
            // Attribute header (4 bytes) + value + padding
            length += 4 + attr.value.len();
            let padding = (4 - (attr.value.len() % 4)) % 4;
            length += padding;
        }
        self.header.message_length = length as u16;
    }

    fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = self.header.to_bytes();
        for attr in &self.attributes {
            bytes.extend_from_slice(&attr.to_bytes());
        }
        bytes
    }

    fn from_bytes(bytes: &[u8]) -> Result<Self, &'static str> {
        if bytes.len() < 20 {
            return Err("STUN message must be at least 20 bytes");
        }

        let header = StunHeader::from_bytes(&bytes[0..20])?;
        let mut attributes = Vec::new();
        
        let mut offset = 20;
        let end = 20 + header.message_length as usize;
        
        while offset < end {
            if offset + 4 > bytes.len() {
                return Err("Invalid attribute header");
            }
            
            let attr_type = u16::from_be_bytes([bytes[offset], bytes[offset + 1]]);
            let length = u16::from_be_bytes([bytes[offset + 2], bytes[offset + 3]]);
            
            if offset + 4 + length as usize > bytes.len() {
                return Err("Invalid attribute length");
            }
            
            let value = bytes[offset + 4..offset + 4 + length as usize].to_vec();
            attributes.push(StunAttribute {
                attr_type,
                length,
                value,
            });
            
            // Move to next attribute (with padding)
            offset += 4 + length as usize;
            let padding = (4 - (length as usize % 4)) % 4;
            offset += padding;
        }

        Ok(StunMessage {
            header,
            attributes,
        })
    }
}

fn create_xor_mapped_address_ipv4(ip: [u8; 4], port: u16, _transaction_id: &[u8; 12]) -> StunAttribute {
    let mut value = Vec::with_capacity(8);
    
    // Reserved byte
    value.push(0x00);
    
    // Family (IPv4 = 0x01)
    value.push(0x01);
    
    // X-Port = port XOR (magic cookie >> 16)
    let xor_port = port ^ (MAGIC_COOKIE >> 16) as u16;
    value.extend_from_slice(&xor_port.to_be_bytes());
    
    // X-Address = IP XOR magic cookie
    let magic_bytes = MAGIC_COOKIE.to_be_bytes();
    for i in 0..4 {
        value.push(ip[i] ^ magic_bytes[i]);
    }
    
    StunAttribute {
        attr_type: ATTR_XOR_MAPPED_ADDRESS,
        length: 8,
        value,
    }
}