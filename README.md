# StatlerScore
A quantitative framework that translates complex cloud infrastructure security risks into an accessible 300–850 scale

## Disclaimer
Statler Score was designed as part of the Online Master of Science in Cybersecurity Practicum at Georgia Institute of Technology. Score estimates are based on the automated analysis of Amazon Web Services (AWS) account posture against the Well-Architected Framework and should not be construed as professional security audit findings. Consult a qualified cloud security practitioner before making architecture changes in production environments.

## How to
Save your credientials as an environment variable or login to AWS with aws configure sso.

## Run the Bureau
python3.13 -m venv venv
source venv/bin/activate
pip3 install -r requirements.txt
uvicorn src.verification.api:app --host 0.0.0.0 --port 8000 

nohup python3 -m uvicorn src.verification.api:app \
    --host 0.0.0.0 --port 8000 --workers 2 \
    > api.log 2>&1 &


sudo tee /etc/systemd/system/statlerscore.service << EOF
[Unit]
Description=StatlerScore Bureau
After=network.target

[Service]
User=ec2-user
WorkingDirectory=/home/ec2-user
EnvironmentFile=/home/ec2-user/.env
ExecStart=/home/ec2-user/venv/bin/uvicorn src.verification.api:app --host 0.0.0.0 --port 8000
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF

## Citing

```bibtex
@software{Statler Score,
  author       = {Hecklinhyde},
  title        = {A quantitative framework that translates complex cloud infrastructure security risks into an accessible 300–850 scale},
  year         = {2026},
  url          = {https://github.com/hecklinhyde/StatlerScore},
  institution  = {Georgia Institute of Technology},
  license      = {MIT}
}
```

## Acknowledgements

This project was made possible by:

**rfc3161ng**
```bibtex
@inproceedings{rfc3161ng,
      title={A simple client library for cryptographic timestamping service implementing the protocol from RFC3161. Based on python-rfc3161 with some additional fixes.}, 
      author={Benjamin Dauvergne,Michael Gebetsroither,and Bas van Oostveen},
}
```

**Coding assistance from ChatGPT by OpenAI**
```bibtex
@software{openai2026chatgpt,
  author={OpenAI},
  title={ChatGPT (GPT-5.2)},
  year={2026},
  url={https://chat.openai.com},
  note={Large language model used for code assistance}
}
```

**Coding assistance from Claude by Anthropic**
```bibtex
@software{Claude,
  author={Anthropic},
  title={Claude (Opus-4.7)},
  year={2026},
  url={https://claude.ai/},
  note={Large language model used for code assistance}
}
```
