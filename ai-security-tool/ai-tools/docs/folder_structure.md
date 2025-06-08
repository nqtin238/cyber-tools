flappie-ai-security/
│
├── README.md                          # Project overview and setup instructions
├── requirements.txt                   # Python dependencies
├── .env.example                      # Environment variables template
├── config.yaml                       # Main configuration file
│
├── core/                             # Core framework components
│   ├── __init__.py
│   ├── lm_studio_client.py          # LM Studio API wrapper
│   ├── security_scanner.py          # Main scanner orchestrator
│   ├── tool_registry.py             # Tool registration and management
│   └── report_generator.py          # Security report generation
│
├── tools/                            # Security testing tools
│   ├── __init__.py
│   ├── base_tool.py                 # Base class for all tools
│   │
│   ├── network/                     # Network security tools
│   │   ├── __init__.py
│   │   ├── nmap_scanner.py          # Nmap integration
│   │   ├── port_analyzer.py         # Port analysis tool
│   │   ├── ssl_tester.py            # SSL/TLS configuration testing
│   │   └── traffic_monitor.py       # Network traffic analysis
│   │
│   ├── services/                    # Service-specific tools
│   │   ├── __init__.py
│   │   ├── mqtt_tester.py           # MQTT security testing
│   │   ├── ssh_auditor.py           # SSH configuration audit
│   │   ├── http_scanner.py          # HTTP/HTTPS testing
│   │   └── reverse_tunnel_detector.py # Reverse tunnel detection
│   │
│   ├── hardware/                    # Hardware interface tools
│   │   ├── __init__.py
│   │   ├── gpio_analyzer.py         # GPIO security analysis
│   │   ├── i2c_scanner.py           # I2C bus security
│   │   ├── bluetooth_tester.py      # Bluetooth security testing
│   │   └── memory_dumper.py         # Memory analysis tools
│   │
│   ├── system/                      # System-level tools
│   │   ├── __init__.py
│   │   ├── user_auditor.py          # User/permission audit
│   │   ├── process_monitor.py       # Process analysis
│   │   ├── file_scanner.py          # File system security
│   │   └── log_analyzer.py          # Log file analysis
│   │
│   └── exploit/                     # Exploitation tools (careful use)
│       ├── __init__.py
│       ├── cve_checker.py           # CVE vulnerability checking
│       ├── fuzzer.py                # Protocol fuzzing
│       └── payload_generator.py     # Test payload generation
│
├── prompts/                         # AI prompts and templates
│   ├── __init__.py
│   ├── system_prompts.py           # System role prompts
│   ├── analysis_prompts.py         # Analysis prompt templates
│   └── report_prompts.py           # Report generation prompts
│
├── models/                          # Data models and schemas
│   ├── __init__.py
│   ├── findings.py                 # Security finding models
│   ├── device_profile.py           # IoT device profile
│   └── tool_schemas.py             # Tool parameter schemas
│
├── utils/                          # Utility functions
│   ├── __init__.py
│   ├── validators.py               # Input validation
│   ├── formatters.py               # Output formatting
│   ├── network_utils.py            # Network utilities
│   └── command_runner.py           # Safe command execution
│
├── reports/                        # Generated reports (gitignored)
│   ├── .gitkeep
│   └── [timestamp]_flappie_security_report.md
│
├── logs/                           # Application logs (gitignored)
│   ├── .gitkeep
│   └── security_scanner.log
│
├── tests/                          # Unit and integration tests
│   ├── __init__.py
│   ├── test_tools/
│   │   ├── test_network_tools.py
│   │   ├── test_service_tools.py
│   │   └── test_hardware_tools.py
│   ├── test_core/
│   │   └── test_lm_studio_client.py
│   └── fixtures/                   # Test data and mocks
│       └── sample_responses.json
│
├── examples/                       # Example usage scripts
│   ├── basic_scan.py              # Simple security scan
│   ├── full_audit.py              # Comprehensive audit
│   └── custom_tool_example.py     # How to add custom tools
│
├── docs/                          # Documentation
│   ├── architecture.md            # System architecture
│   ├── tool_development.md        # How to create new tools
│   ├── api_reference.md           # API documentation
│   └── security_considerations.md # Security best practices
│
└── scripts/                       # Utility scripts
    ├── setup.sh                   # Initial setup script
    ├── install_dependencies.sh    # Dependency installation
    └── generate_tool_docs.py      # Auto-generate tool documentation