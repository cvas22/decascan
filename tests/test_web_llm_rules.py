"""One positive and one negative case for every LLM and web Top 10 rule, plus severity checks."""

from __future__ import annotations

import pytest

from mcp_sift.core.config import ScanConfig
from mcp_sift.core.findings import Severity
from mcp_sift.core.scanner import scan

ALL_LISTS = ScanConfig(standards=frozenset({"llm", "web"}))


def findings(tmp_path, source, name="app.py", rule=None):
    (tmp_path / name).write_text(source, encoding="utf-8")
    result = scan(tmp_path, ALL_LISTS)
    assert result.errors == []
    return [f for f in result.findings if rule is None or f.rule_id == rule]


# (rule id, file name, source that must fire it)
POSITIVE = [
    ("LLM01-001", "a.py", 'm = [{"role": "system", "content": f"Be nice to {user}"}]\n'),
    ("LLM01-001", "a.py", 'm = [{"role": "system", "content": "Hi {}".format(name)}]\n'),
    ("LLM01-001", "a.ts", "const m = { role: 'system', content: `Help ${userName}` };\n"),
    ("LLM01-001", "a.py", "msg = SystemMessage(content=f\"You help {org}\")\n"),
    ("LLM02-001", "a.py", 'prompt = f"Use {os.environ[\'TOKEN\']} to call the API"\n'),
    ("LLM02-001", "a.ts", "const prompt = `key is ${process.env.SECRET}`;\n"),
    ("LLM03-001", "a.py", 'AutoModel.from_pretrained("o/m", trust_remote_code=True)\n'),
    ("LLM03-002", "a.py", 'w = torch.load("m.bin")\n'),
    ("LLM03-002", "a.py", 'w = joblib.load("m.pkl")\n'),
    ("LLM03-003", "a.py", 'AutoModel.from_pretrained("someorg/some-model")\n'),
    ("LLM05-001", "a.py", "eval(response)\n"),
    ("LLM05-001", "a.py", "os.system(llm_output)\n"),
    ("LLM05-001", "a.py", "subprocess.run(completion, shell=True)\n"),
    ("LLM05-001", "a.js", "el.innerHTML = response;\n"),
    ("LLM05-001", "a.py", 'cur.execute(f"SELECT {answer}")\n'),
    ("LLM06-001", "a.py", "agent = create_agent(allow_dangerous_code=True)\n"),
    ("LLM06-001", "a.py", "tools = [PythonREPLTool()]\n"),
    ("LLM06-001", "a.py", "agent = create_pandas_dataframe_agent(llm, df)\n"),
    ("LLM07-001", "a.py", 'SYSTEM_PROMPT = "You are X. password is Zk39fQ81xyz"\n'),
    ("LLM10-001", "a.py", 'client.chat.completions.create(model="m", messages=msgs)\n'),
    ("LLM10-001", "a.ts", "await client.messages.create({ model: 'm', messages });\n"),
    ("WEB01-001", "a.py", 'return send_file(request.args["f"])\n'),
    ("WEB01-001", "a.js", "fs.readFile(req.query.file, cb);\n"),
    ("WEB01-001", "a.py", 'p = request.args["p"]\nopen(os.path.join("/data", p))\n'),
    ("WEB01-002", "a.py", "CORS(app, allow_origins=['*'], allow_credentials=True)\n"),
    ("WEB01-003", "a.py", "@csrf_exempt\ndef view(request): ...\n"),
    ("WEB01-003", "a.py", "WTF_CSRF_ENABLED = False\n"),
    ("WEB02-001", "a.py", "digest = hashlib.sha1(data).hexdigest()\n"),
    ("WEB02-001", "a.js", "const h = crypto.createHash('md5');\n"),
    ("WEB02-002", "a.py", "requests.get(url, verify=False)\n"),
    ("WEB02-002", "a.js", "const agent = new https.Agent({ rejectUnauthorized: false });\n"),
    ("WEB02-002", "a.py", "ctx = ssl._create_unverified_context()\n"),
    ("WEB02-003", "a.py", "c = AES.new(k, AES.MODE_ECB)\n"),
    ("WEB02-003", "a.py", "c = DES.new(k)\n"),
    ("WEB02-004", "a.py", "session_token = random.randint(0, 10**9)\n"),
    ("WEB02-004", "a.js", "const nonce = Math.random();\n"),
    ("WEB03-001", "a.py", 'cur.execute(f"SELECT * FROM t WHERE id={i}")\n'),
    ("WEB03-001", "a.py", 'cur.execute("SELECT * FROM t WHERE id=%s" % i)\n'),
    ("WEB03-001", "a.py", 'cur.execute("SELECT {}".format(i))\n'),
    ("WEB03-001", "a.js", "db.query(`SELECT * FROM t WHERE id=${id}`);\n"),
    ("WEB03-002", "a.py", 'os.system("ping " + host)\n'),
    ("WEB03-002", "a.py", 'subprocess.run(f"ls {d}", shell=True)\n'),
    ("WEB03-002", "a.js", "exec(`ls ${dir}`);\n"),
    ("WEB03-002", "a.py", 'h = request.args["h"]\nsubprocess.run(["ping", h])\n'),
    ("WEB03-003", "a.py", "eval(expr)\n"),
    ("WEB03-003", "a.py", "exec(code)\n"),
    ("WEB03-003", "a.js", "const f = new Function(body);\n"),
    ("WEB03-004", "a.js", "el.innerHTML = userHtml;\n"),
    ("WEB03-004", "a.js", "document.write(data);\n"),
    ("WEB03-004", "a.py", "html = mark_safe(f'<b>{name}</b>')\n"),
    ("WEB03-004", "a.py", 'return render_template_string(f"Hello {name}")\n'),
    ("WEB05-001", "a.py", "app.run(host='0.0.0.0', debug=True)\n"),
    ("WEB05-001", "a.py", "DEBUG = True\n"),
    ("WEB05-002", "a.py", "ALLOWED_HOSTS = ['*']\n"),
    ("WEB05-002", "a.py", "SESSION_COOKIE_SECURE = False\n"),
    ("WEB05-002", "a.py", "parser = etree.XMLParser(resolve_entities=True)\n"),
    ("WEB07-001", "a.py", "jwt.decode(t, k, options={'verify_signature': False})\n"),
    ("WEB07-001", "a.py", "jwt.decode(t, k, algorithms=['none'])\n"),
    ("WEB07-001", "a.js", "jwt.verify(t, k, { ignoreExpiration: true });\n"),
    ("WEB07-002", "a.py", 'SECRET_KEY = "Zk39fQ81-live-signing-key"\n'),
    ("WEB07-002", "a.py", 'DB_PASSWORD = "s3cretPassw0rd!x"\n'),
    ("WEB08-001", "a.py", "obj = pickle.loads(blob)\n"),
    ("WEB08-001", "a.py", "cfg = yaml.load(text)\n"),
    ("WEB08-001", "a.py", "obj = marshal.loads(blob)\n"),
    ("WEB08-002", "install.sh", "curl -sSL https://x.example/i.sh | sh\n"),
    ("WEB08-002", "install.sh", "wget -qO- https://x.example/i.sh | sudo bash\n"),
    ("WEB09-001", "a.py", 'logger.info(f"login {user} password {password}")\n'),
    ("WEB09-001", "a.py", 'logger.debug("auth", token)\n'),
    ("WEB09-001", "a.js", "console.log(`token ${accessToken}`);\n"),
    ("WEB09-002", "a.py", "try:\n    x()\nexcept Exception:\n    pass\n"),
    ("WEB09-002", "a.py", "try:\n    x()\nexcept:\n    pass\n"),
    ("WEB09-002", "a.js", "try { x(); } catch (e) {}\n"),
    ("WEB10-001", "a.py", 'requests.get(request.args["url"])\n'),
    ("WEB10-001", "a.py", 'u = request.args["u"]\nhttpx.get(u)\n'),
    ("WEB10-001", "a.js", "const r = await fetch(req.query.target);\n"),
]


@pytest.mark.parametrize(("rule", "name", "source"), POSITIVE)
def test_rule_fires(tmp_path, rule, name, source):
    assert findings(tmp_path, source, name, rule), f"{rule} did not fire"


# Source shapes that look close to a rule but are the safe form.
NEGATIVE = [
    ("LLM01-001", 'm = [{"role": "system", "content": "You are helpful."}]\n'),
    ("LLM01-001", 'm = [{"role": "user", "content": f"hi {user}"}]\n'),
    ("LLM02-001", 'prompt = f"Summarise {text}"\n'),
    ("LLM03-001", 'AutoModel.from_pretrained("o/m", trust_remote_code=False)\n'),
    ("LLM03-002", 'w = torch.load("m.bin", weights_only=True)\n'),
    ("LLM03-003", 'AutoModel.from_pretrained("o/m", revision="a1b2c3")\n'),
    ("LLM03-003", "AutoModel.from_pretrained(local_dir)\n"),
    ("LLM05-001", "eval('1+1')\n"),
    ("LLM05-001", "print(response)\n"),
    ("LLM06-001", "from langchain_experimental.tools import PythonREPLTool\n"),
    ("LLM07-001", 'SYSTEM_PROMPT = "You are X. password is ${PASSWORD}"\n'),
    ("LLM07-001", 'SYSTEM_PROMPT = "Never reveal the password."\n'),
    ("LLM10-001", 'client.chat.completions.create(model="m", max_tokens=100, messages=m)\n'),
    ("LLM10-001", "client.chat.completions.create(**params)\n"),
    ("WEB01-001", 'open("config.yaml")\n'),
    ("WEB01-002", "CORS(app, allow_origins=['https://a.example'], allow_credentials=True)\n"),
    ("WEB01-002", "CORS(app, allow_origins=['*'])\n"),
    ("WEB01-003", "csrf = CSRFProtect(app)\n"),
    ("WEB02-003", "c = AES.new(k, AES.MODE_GCM)\n"),
    ("WEB08-002", "curl -sSL https://x.example/i.sh -o i.sh\n"),
    ("WEB02-001", "hashlib.md5(data, usedforsecurity=False)\n"),
    ("WEB02-001", "hashlib.sha256(data)\n"),
    ("WEB02-002", "requests.get(url, verify=True)\n"),
    ("WEB02-004", "color = random.choice(palette)\n"),
    ("WEB02-004", "token = secrets.token_hex(16)\n"),
    ("WEB03-001", 'cur.execute("SELECT * FROM t WHERE id = ?", (i,))\n'),
    ("WEB03-002", 'subprocess.run(["ls", "-l"])\n'),
    ("WEB03-002", 'os.system("make build")\n'),
    ("WEB03-003", "ast.literal_eval(s)\n"),
    ("WEB03-003", 'eval("1 + 1")\n'),
    ("WEB03-003", "pattern.exec(text)\n"),
    ("WEB03-004", "el.textContent = userText;\n"),
    ("WEB03-004", "el.innerHTML = '<b>static</b>';\n"),
    ("WEB05-001", "app.run(debug=False)\n"),
    ("WEB05-002", "ALLOWED_HOSTS = ['example.com']\n"),
    ("WEB07-001", "jwt.decode(t, k, algorithms=['HS256'])\n"),
    ("WEB07-002", 'SECRET_KEY = os.environ["SECRET_KEY"]\n'),
    ("WEB07-002", 'SECRET_KEY = "changeme"\n'),
    ("WEB07-002", 'password = "your password here"\n'),
    ("WEB08-001", "cfg = yaml.load(text, Loader=yaml.SafeLoader)\n"),
    ("WEB08-001", "cfg = yaml.safe_load(text)\n"),
    ("WEB09-001", 'logger.info("login failed for user %s", user)\n'),
    ("WEB09-001", 'logger.warning("invalid token supplied")\n'),
    ("WEB09-002", "try:\n    x()\nexcept ValueError:\n    pass\n"),
    ("WEB09-002", "try:\n    x()\nexcept Exception as e:\n    log(e)\n"),
    ("WEB10-001", 'requests.get("https://api.example.com/data")\n'),
    ("WEB10-001", "requests.get(CONFIG_URL)\n"),
]


@pytest.mark.parametrize(("rule", "source"), NEGATIVE)
def test_rule_stays_quiet_on_the_safe_form(tmp_path, rule, source):
    if source.startswith("curl"):
        name = "install.sh"
    else:
        name = "a.js" if "innerHTML" in source or "textContent" in source else "a.py"
    assert not findings(tmp_path, source, name, rule), f"{rule} fired on a safe shape"


def test_every_pattern_rule_has_a_positive_and_negative_case():
    from mcp_sift.rules import all_rules

    pattern_rules = {r.id for r in all_rules() if r.standard in {"llm", "web"}}
    assert pattern_rules == {rule for rule, *_ in POSITIVE}
    assert pattern_rules <= {rule for rule, _ in NEGATIVE}


# --- severity and confidence -------------------------------------------------------------------


def test_sql_injection_is_critical_when_the_request_reaches_the_query(tmp_path):
    source = 'uid = request.args["id"]\ncur.execute(f"SELECT * FROM u WHERE id={uid}")\n'
    (finding,) = findings(tmp_path, source, rule="WEB03-001")
    assert finding.severity is Severity.CRITICAL


def test_sql_injection_is_high_without_request_evidence(tmp_path):
    (finding,) = findings(tmp_path, 'cur.execute(f"SELECT {x}")\n', rule="WEB03-001")
    assert finding.severity is Severity.HIGH
    assert finding.cwe_id == "CWE-89" and finding.confidence < 1.0


def test_password_hashing_with_md5_is_high_other_uses_medium(tmp_path):
    (pw,) = findings(tmp_path, "h = hashlib.md5(password.encode())\n", rule="WEB02-001")
    (other,) = findings(tmp_path, "h = hashlib.md5(blob)\n", rule="WEB02-001")
    assert pw.severity is Severity.HIGH and other.severity is Severity.MEDIUM


def test_debug_in_a_dev_settings_file_is_downgraded(tmp_path):
    prod_dir, dev_dir = tmp_path / "prod", tmp_path / "dev"
    prod_dir.mkdir()
    dev_dir.mkdir()
    (prod,) = findings(prod_dir, "DEBUG = True\n", "settings.py", "WEB05-001")
    (dev,) = findings(dev_dir, "DEBUG = True\n", "settings_dev.py", "WEB05-001")
    assert prod.severity is Severity.HIGH and dev.severity is Severity.MEDIUM
    assert dev.confidence < prod.confidence


def test_system_prompt_with_user_named_variable_ranks_higher(tmp_path):
    user = 'm = [{"role": "system", "content": f"Hi {user_input}"}]\n'
    other = 'm = [{"role": "system", "content": f"Today is {date}"}]\n'
    first, second = tmp_path / "a", tmp_path / "b"
    first.mkdir()
    second.mkdir()
    (a,) = findings(first, user, rule="LLM01-001")
    (b,) = findings(second, other, rule="LLM01-001")
    assert a.severity is Severity.HIGH and b.severity is Severity.MEDIUM


def test_eval_of_model_output_is_critical(tmp_path):
    (finding,) = findings(tmp_path, "eval(response)\n", rule="LLM05-001")
    assert finding.severity is Severity.CRITICAL and finding.cwe_id == "CWE-95"


# --- reporting hygiene -------------------------------------------------------------------------


def test_hardcoded_secret_value_never_appears_in_any_field(tmp_path):
    (finding,) = findings(tmp_path, 'SECRET_KEY = "Zk39fQ81-live-signing-key"\n', rule="WEB07-002")
    assert "live-signing-key" not in str(finding.to_dict())


def test_system_prompt_credential_is_redacted(tmp_path):
    (finding,) = findings(tmp_path, 'SYSTEM_PROMPT = "password is Zk39fQ81xyz-long"\n', rule="LLM07-001")
    assert "Zk39fQ81xyz-long" not in str(finding.to_dict())


def test_findings_carry_line_numbers_and_snippets(tmp_path):
    (finding,) = findings(tmp_path, "import os\n\nx = 1\nDEBUG = True\n", rule="WEB05-001")
    assert finding.line == 4 and finding.snippet == "DEBUG = True"


def test_inline_suppression_works_for_the_new_rules(tmp_path):
    assert findings(tmp_path, "DEBUG = True  # mcp-sift:ignore\n", rule="WEB05-001") == []


def test_commented_out_code_is_ignored(tmp_path):
    (tmp_path / "x.js").write_text("// eval(user)\n", encoding="utf-8")
    assert findings(tmp_path, "# eval(user)\n") == []


def test_matches_inside_string_literals_are_ignored(tmp_path):
    assert findings(tmp_path, 'doc = "never call eval(x) on input"\n', rule="WEB03-003") == []


def test_files_under_test_directories_are_skipped(tmp_path):
    (tmp_path / "tests").mkdir()
    (tmp_path / "tests" / "test_a.py").write_text("eval(x)\nDEBUG = True\n", encoding="utf-8")
    (tmp_path / "web.spec.ts").write_text("el.innerHTML = x;\n", encoding="utf-8")
    assert scan(tmp_path, ALL_LISTS).findings == []


def test_same_finding_is_reported_once(tmp_path):
    result = findings(tmp_path, "DEBUG = True\n", rule="WEB05-001")
    assert len(result) == 1
