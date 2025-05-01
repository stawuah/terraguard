#[cfg(test)]

mod tests {
    // Or adjust path based on your module structure
    use serde_json::json;
    use rules;

    #[test]
    fn test_check_open_ingress() {
        let validator = FastValidator::new();

        let resource = json!({
            "ingress": [
                {
                    "from_port": 22,
                    "to_port": 22,
                    "cidr_blocks": ["0.0.0.0/0"]
                }
            ]
        });

        let issues = validator.check_open_ingress("aws_security_group.test".to_string(), &resource);
        assert_eq!(issues.len(), 1);
        assert!(issues[0].message.contains("0.0.0.0/0"));
        assert!(issues[0].message.contains("SSH"));

        let resource = json!({
            "ingress": [
                {
                    "from_port": 443,
                    "to_port": 443,
                    "cidr_blocks": ["10.0.0.0/8"]
                }
            ]
        });

        let issues = validator.check_open_ingress("aws_security_group.test".to_string(), &resource);
        assert_eq!(issues.len(), 0);
    }

    #[test]
    fn test_check_ports() {
        let validator = FastValidator::new();

        let resource = json!({
            "ingress": [
                {
                    "from_port": 22,
                    "to_port": 22,
                    "cidr_blocks": ["10.0.0.0/8"]
                }
            ]
        });

        let issues = validator.check_ports("aws_security_group.test".to_string(), &resource);
        assert_eq!(issues.len(), 1);
        assert!(issues[0].message.contains("22"));
        assert!(issues[0].message.contains("SSH"));

        let resource = json!({
            "ingress": [
                {
                    "from_port": 1000,
                    "to_port": 5000,
                    "cidr_blocks": ["10.0.0.0/8"]
                }
            ]
        });

        let issues = validator.check_ports("aws_security_group.test".to_string(), &resource);
        assert_eq!(issues.len(), 1);
        assert!(issues[0].message.contains("1000-5000"));
    }
}
