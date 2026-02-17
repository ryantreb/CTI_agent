# CTI Agent - Ubuntu Setup Guide

## Your Environment

Based on your setup:
- **OS**: Ubuntu 24
- **GPU**: RTX 3060 (12GB VRAM)
- **Python Environment**: `~/ai-dev` (activated via `aidev` alias)
- **Editor**: VS Code

---

## Step 1: Activate Your Virtual Environment

**Every time you open a new terminal**, you need to reactivate your virtual environment. The venv doesn't persist across terminal sessions.

### Option A: Use Your Alias (Fastest)
```bash
aidev
```

### Option B: Manual Activation
```bash
source ~/ai-dev/bin/activate
```

### How to Know You're in the Venv
When activated, you'll see `(ai-dev)` at the beginning of your prompt:
```
(ai-dev) ryan@ubuntu:~$
```

If you DON'T see `(ai-dev)`, you're NOT in the virtual environment and pip will fail.

### Setting Up the Alias (If Not Already Done)
If `aidev` doesn't work, add the alias to your shell:

```bash
# Add to your ~/.bashrc
echo 'alias aidev="source ~/ai-dev/bin/activate"' >> ~/.bashrc

# Reload bashrc
source ~/.bashrc

# Now use the alias
aidev
```

### Deactivating the Venv (When Done)
```bash
deactivate
```
Your prompt will return to normal (no `(ai-dev)` prefix).

### Quick Verification Commands
```bash
# Check if venv is active
echo $VIRTUAL_ENV
# Should show: /home/ryan/ai-dev

# Check which Python you're using
which python
# Should show: /home/ryan/ai-dev/bin/python

# Check which pip you're using  
which pip
# Should show: /home/ryan/ai-dev/bin/pip
```

**Why pip fails without this**: Ubuntu 24 blocks system-wide pip installs (PEP 668). Your virtual environment bypasses this.

---

## Step 2: Install MCP Servers

With your venv active:

```bash
# GTI (VirusTotal/Google Threat Intelligence)
pip install gti-mcp

# Feedly Threat Intelligence
pip install feedly-mcp

# Multi-source IOC enrichment (optional but recommended)
pip install fastmcp-threatintel

# Verification Agent dependencies
pip install httpx pydantic tenacity python-dotenv

# Verify installations
pip list | grep -E "gti|feedly|threatintel|httpx|pydantic"
```

### If pip still fails

Try with the `--break-system-packages` flag (only if venv activation didn't work):

```bash
pip install gti-mcp --break-system-packages
```

Or ensure you're in the venv:
```bash
which pip
# Should show: /home/ryan/ai-dev/bin/pip
# NOT: /usr/bin/pip
```

---

## Step 3: Install uvx (Universal Package Runner)

The MCP servers use `uvx` to run. Install it:

```bash
# Install pipx first (manages isolated tools)
pip install pipx
pipx ensurepath

# Install uv (includes uvx)
pipx install uv

# Verify
uvx --version
```

**Alternative** if pipx gives issues:
```bash
pip install uv
# Then use: python -m uv instead of uvx
```

---

## Step 4: Set Up API Keys

Create your environment file:

```bash
# Navigate to project
cd ~/ai-dev/junior-threat-intel-agent

# Copy template
cp .env.example .env

# Edit with your keys
code .env
# Or: nano .env
```

Add your keys:
```bash
# Required
VT_API_KEY=your_virustotal_key
FEEDLY_ACCESS_TOKEN=your_feedly_token

# Optional
ABUSEIPDB_API_KEY=your_abuseipdb_key
```

Load them into your shell:
```bash
# Add to your ~/.bashrc for persistence
echo 'export $(cat ~/ai-dev/junior-threat-intel-agent/.env | xargs)' >> ~/.bashrc
source ~/.bashrc

# Or load temporarily for this session
export $(cat .env | xargs)
```

---

## Step 5: Extract the Project

```bash
# Activate venv
aidev

# Navigate to your AI dev directory
cd ~/ai-dev

# Extract the project (assuming you downloaded the zip)
unzip junior-threat-intel-agent.zip

# Enter project directory
cd junior-threat-intel-agent

# View structure
ls -la
```

---

## Step 6: Test MCP Servers

Verify the servers work:

```bash
# Test GTI (requires VT_API_KEY set)
uvx gti_mcp --help

# Test Feedly (requires FEEDLY_ACCESS_TOKEN set)
uvx feedly-mcp --help
```

If you get "command not found" for uvx:
```bash
# Add to PATH
export PATH="$HOME/.local/bin:$PATH"
echo 'export PATH="$HOME/.local/bin:$PATH"' >> ~/.bashrc
```

---

## Step 7: Run Evaluation Graders (Test)

```bash
cd ~/ai-dev/junior-threat-intel-agent

# Make sure you're in venv
aidev

# Test the graders
python evaluation/graders/ttp_coverage_grader.py
python evaluation/graders/ioc_fidelity_grader.py
python evaluation/graders/framework_compliance_grader.py

# Test the verification agent (requires VT_API_KEY set)
python skills/verify-claims/verification_agent.py
```

---

## Quick Reference: Your Workflow

```bash
# 1. Activate environment
aidev

# 2. Navigate to project
cd ~/ai-dev/junior-threat-intel-agent

# 3. Load API keys (if not in bashrc)
export $(cat .env | xargs)

# 4. Use with Claude Code or as reference for your agent work
```

---

## Troubleshooting

### "externally-managed-environment" error
```bash
# Solution: Activate your venv first
aidev
# Then retry pip install
```

### "uvx: command not found"
```bash
# Add to PATH
export PATH="$HOME/.local/bin:$PATH"
# Make permanent
echo 'export PATH="$HOME/.local/bin:$PATH"' >> ~/.bashrc
source ~/.bashrc
```

### "No module named X"
```bash
# Verify you're in venv
which python
# Should show: /home/ryan/ai-dev/bin/python

# If not, activate
aidev
```

### Permission denied on apt
```bash
# Don't use apt for Python packages - use pip in venv instead
# apt is for system packages, pip is for Python packages
```

### MCP server won't start
```bash
# Check API key is set
echo $VT_API_KEY

# If empty, load your .env
export $(cat .env | xargs)
```

---

## Directory Locations

| What | Path |
|------|------|
| Virtual Environment | `~/ai-dev/` |
| Project Root | `~/ai-dev/junior-threat-intel-agent/` |
| Skills | `~/ai-dev/junior-threat-intel-agent/skills/` |
| Evaluation Graders | `~/ai-dev/junior-threat-intel-agent/evaluation/graders/` |
| Reports Output | `~/ai-dev/junior-threat-intel-agent/reports/` |

---

## 🚀 Quick Reference Card

**Print this or keep it handy:**

```
┌─────────────────────────────────────────────────────────┐
│  EVERY NEW TERMINAL SESSION:                            │
│                                                         │
│    aidev                                                │
│                                                         │
│  Or if alias not set:                                   │
│                                                         │
│    source ~/ai-dev/bin/activate                         │
│                                                         │
│  You'll know it worked when you see:                    │
│                                                         │
│    (ai-dev) ryan@ubuntu:~$                              │
│                                                         │
│  Then navigate to project:                              │
│                                                         │
│    cd ~/ai-dev/junior-threat-intel-agent                │
│                                                         │
└─────────────────────────────────────────────────────────┘
```

---

*Tailored for your Ubuntu + RTX 3060 + ~/ai-dev environment*
