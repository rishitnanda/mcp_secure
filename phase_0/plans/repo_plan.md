mcp-secure-suite/
│
├── docs/
│   └── mcp_security_paper.pdf   # Your research paper PDF
│
├── mcp_shield/                  # Layer 1: The Proxy
│   ├── src/
│   │   ├── gateway.py           # Async JSON-RPC interceptor
│   │   └── schemas.py           # Strict Pydantic models
│   └── requirements.txt
│
├── mcp_box/                     # Layer 2: The Sandbox
│   ├── src/
│   │   └── sandbox.py           # Python-Docker virtualization hook
│   └── requirements.txt
│
├── tests/                       # Integrated Test Suite
│   ├── test_shield_isolated.py
│   ├── test_box_isolated.py
│   └── test_end_to_end.py       # Simulates an attack passing through both layers
│
├── docker-compose.yml           # Boots the whole ecosystem with one command
└── README.md                    # The "Showroom" landing page