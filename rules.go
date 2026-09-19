package main

import (
	"regexp"
)

// Severity levels used across all rules.
const (
	SevCritical = "critical"
	SevHigh     = "high"
	SevMedium   = "medium"
	SevLow      = "low"
)

// Category groups rules so the report can summarize by theme.
const (
	CatInjection     = "injection"
	CatSecret        = "secret"
	CatCrypto        = "weak-crypto"
	CatDeserial      = "deserialization"
	CatCommandExec   = "command-execution"
	CatPathTraversal = "path-traversal"
	CatMemory        = "memory-unsafe"
	CatCodeEval      = "code-evaluation"
	CatRandom        = "insecure-random"
	CatSSRF          = "ssrf"
)

// Rule describes one static check: what to look for and how to fix it.
type Rule struct {
	ID        string
	Name      string
	Category  string
	Severity  string
	Languages []string // "python", "javascript", "go", "java", "c", "csharp", "php", "ruby", "generic"
	Pattern   *regexp.Regexp
	Message   string
	Fix       string
}

func re(p string) *regexp.Regexp {
	return regexp.MustCompile(p)
}

var allRules = []*Rule{
	// ---------------- Command execution ----------------
	{
		ID: "CME-001", Name: "os.system() shell execution", Category: CatCommandExec,
		Severity: SevCritical, Languages: []string{"python"},
		Pattern: re(`\bos\.(system|popen|spawn[lv]*)\s*\(`),
		Message: "Runs an OS command from the program; if input reaches here it is command injection.",
		Fix:     "Prefer subprocess.run with a list argument and shell=False; never splice user input into a shell string.",
	},
	{
		ID: "CME-002", Name: "subprocess with shell=True", Category: CatCommandExec,
		Severity: SevCritical, Languages: []string{"python"},
		Pattern: re(`subprocess\.(run|call|check_call|check_output|Popen)\s*\([^)]*\bshell\s*=\s*True`),
		Message: "subprocess invoked through the shell, enabling command injection when arguments contain user data.",
		Fix:     "Remove shell=True and pass the command as a list, e.g. subprocess.run([\"git\", \"status\"]).",
	},
	{
		ID: "CME-003", Name: "eval() of code", Category: CatCodeEval,
		Severity: SevCritical, Languages: []string{"python"},
		Pattern: re(`\beval\s*\(|^\s*exec\s*\(`),
		Message: "Evaluates arbitrary Python from a string; malicious input can execute code.",
		Fix:     "Avoid eval/exec. Use ast.literal_eval for literals or a real parser for your data format.",
	},
	{
		ID: "CME-004", Name: "exec.Command with shell", Category: CatCommandExec,
		Severity: SevHigh, Languages: []string{"go"},
		Pattern: re(`exec\.Command\s*\(\s*["/]+`),
		Message: "Launches an external command; verify the arguments cannot be user controlled.",
		Fix:     "Pass a fixed argument list, never build a shell command string, and validate inputs.",
	},
	{
		ID: "CME-005", Name: "Runtime.exec()", Category: CatCommandExec,
		Severity: SevCritical, Languages: []string{"java"},
		Pattern: re(`Runtime\s*\.\s*getRuntime\s*\(\s*\)\s*\.\s*exec\s*\(`),
		Message: "Executes an OS command; user input reaching here is a command injection primitive.",
		Fix:     "Validate and constrain input; prefer ProcessBuilder with a non-shell argument list.",
	},
	{
		ID: "CME-006", Name: "PHP system/shell functions", Category: CatCommandExec,
		Severity: SevCritical, Languages: []string{"php"},
		Pattern: re(`\b(system|shell_exec|exec|passthru|proc_open|popen)\s*\(`),
		Message: "Executes shell commands; never pass unfiltered user input to these functions.",
		Fix:     "Avoid shell functions, or escape input with escapeshellarg() and validate against a whitelist.",
	},
	{
		ID: "CME-007", Name: "child_process.exec()", Category: CatCommandExec,
		Severity: SevHigh, Languages: []string{"javascript"},
		Pattern: re(`child_process\s*\.\s*exec\s*\(`),
		Message: "Runs a command through a shell; user input in the command is command injection.",
		Fix:     "Use child_process.execFile with a command array, or spawn with a non-shell argument list.",
	},
	{
		ID: "CME-008", Name: "C system()", Category: CatCommandExec,
		Severity: SevHigh, Languages: []string{"c"},
		Pattern: re(`\bsystem\s*\(`),
		Message: "Invokes the shell from C; input concatenated into the string can execute commands.",
		Fix:     "Use fork + execve with argv, never system(), and sanitize any dynamic input.",
	},

	// ---------------- SQL injection ----------------
	{
		ID: "SQL-001", Name: "SQL query string concatenation", Category: CatInjection,
		Severity: SevCritical, Languages: []string{"python", "javascript", "go", "java", "php", "csharp", "ruby"},
		Pattern: re(`(?i)(SELECT|UPDATE|INSERT|DELETE)\b[^\n;]*\b(WHERE|VALUES|SET)\b[^\n;]*(\+|fmt\.Sprintf|\.format\(|f["']|%s)`),
		Message: "SQL statement built by string concatenation or formatting; user input in the value is SQL injection.",
		Fix:     "Use parameterized queries / prepared statements with bind placeholders, never string interpolation.",
	},
	{
		ID: "SQL-002", Name: "raw execute with concat", Category: CatInjection,
		Severity: SevHigh, Languages: []string{"python", "javascript", "go", "java", "php", "csharp"},
		Pattern: re(`(?i)(execute|executeQuery|query|Exec|prepared|Prepare)\s*\([^)]*(SELECT|INSERT|UPDATE|DELETE)[^)]*(\+|\||%s|\.format|f["'])`),
		Message: "Query call building SQL dynamically instead of binding parameters.",
		Fix:     "Pass parameters as bound arguments through the driver/ORM; never embed them in the SQL string.",
	},

	// ---------------- Hardcoded secrets ----------------
	{
		ID: "SEC-001", Name: "hardcoded password/secret", Category: CatSecret,
		Severity: SevHigh, Languages: []string{"generic"},
		Pattern: re(`(?i)(password|passwd|secret|api[_ ]?key|access[_ ]?key|token|auth)\s*[:=]\s*["'][^"'$\s]{8,}["']`),
		Message: "A credential appears as a literal value in source.",
		Fix:     "Move the value to an environment variable, secret manager, or config file outside the repository.",
	},
	{
		ID: "SEC-002", Name: "credentials in URL", Category: CatSecret,
		Severity: SevHigh, Languages: []string{"generic"},
		Pattern: re(`(?i)(https?|mysql|postgres|redis|amqp)://[^/\s:@]+:[^@\s/]+@`),
		Message: "Username:password embedded directly in a connection URL.",
		Fix:     "Read credentials from environment variables and inject at runtime instead of hardcoding.",
	},
	{
		ID: "SEC-003", Name: "private key in source", Category: CatSecret,
		Severity: SevCritical, Languages: []string{"generic"},
		Pattern: re(`-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----`),
		Message: "A private key is checked into the scanned source.",
		Fix:     "Remove the key from the repository, rotate it, and load it from a protected path at runtime.",
	},

	// ---------------- Weak crypto ----------------
	{
		ID: "CRY-001", Name: "MD5/SHA1 usage", Category: CatCrypto,
		Severity: SevMedium, Languages: []string{"generic"},
		Pattern: re(`(?i)\b(md5|sha1)\s*\(|MessageDigest\s*\.\s*getInstance\s*\(\s*["'](MD5|SHA-1)|hashlib\.(md5|sha1)|Crypto::(MD5|SHA1)`),
		Message: "MD5 or SHA-1 is used; both are broken for security purposes (collisions, no preimage resistance needed).",
		Fix:     "Use SHA-256/SHA-3 for integrity or Argon2/bcrypt for passwords.",
	},
	{
		ID: "CRY-002", Name: "DES/3DES/RC4/ECB", Category: CatCrypto,
		Severity: SevHigh, Languages: []string{"generic"},
		Pattern: re(`(?i)\b(DES|DESede|3DES|RC4|ECB)\b`),
		Message: "A legacy cipher or mode is in use; these are cryptographically weak.",
		Fix:     "Use AES-GCM or ChaCha20-Poly1305 with random nonces.",
	},

	// ---------------- Deserialization ----------------
	{
		ID: "DSR-001", Name: "pickle.loads", Category: CatDeserial,
		Severity: SevCritical, Languages: []string{"python"},
		Pattern: re(`\bpickle\s*\.\s*(loads|load)\s*\(`),
		Message: "Unpickling untrusted data can execute arbitrary code during object construction.",
		Fix:     "Never unpickle untrusted input; use JSON or a format with no code execution.",
	},
	{
		ID: "DSR-002", Name: "yaml.load unsafe", Category: CatDeserial,
		Severity: SevHigh, Languages: []string{"python"},
		Pattern: re(`yaml\.load\s*\(`),
		Message: "yaml.load can instantiate arbitrary Python objects when the loader is unsafe.",
		Fix:     "Use yaml.safe_load for untrusted YAML.",
	},
	{
		ID: "DSR-003", Name: "Java ObjectInputStream", Category: CatDeserial,
		Severity: SevCritical, Languages: []string{"java"},
		Pattern: re(`ObjectInputStream|ObjectInputFilter|readObject\s*\(`),
		Message: "Deserializing objects with ObjectInputStream can lead to gadget-chain code execution.",
		Fix:     "Avoid native Java serialization for untrusted data; use a safe format and ObjectInputFilter allowlists.",
	},
	{
		ID: "DSR-004", Name: "PHP unserialize", Category: CatDeserial,
		Severity: SevHigh, Languages: []string{"php"},
		Pattern: re(`\bunserialize\s*\(`),
		Message: "unserialize() on untrusted data can trigger magic methods and code execution.",
		Fix:     "Use JSON and allowlist-validate structures; never unserialize user input.",
	},
	{
		ID: "DSR-005", Name: ".NET binary deserialization", Category: CatDeserial,
		Severity: SevCritical, Languages: []string{"csharp"},
		Pattern: re(`BinaryFormatter|LosFormatter|NetDataContractSerializer|DataContractSerializer\s*\.\s*ReadObject`),
		Message: "BinaryFormatter-style deserialization of untrusted data is a code-execution vector.",
		Fix:     "Use System.Text.Json or Newtonsoft with type allowlists instead of BinaryFormatter.",
	},

	// ---------------- Path traversal ----------------
	{
		ID: "PTH-001", Name: "file path from user input", Category: CatPathTraversal,
		Severity: SevMedium, Languages: []string{"python", "javascript", "go", "java", "php"},
		Pattern: re(`(open|file_get_contents|readFile|os\.Open|new File|new BufferedReader|fs\.(read|write|append))\([^)]*\b(user|input|req|request|filename|name|path|param)\b`),
		Message: "A file operation appears to use a value derived from request/user input without sanitization.",
		Fix:     "Resolve the path, canonicalize it, and ensure it stays inside the allowed base directory (filepath.Clean, realpath).",
	},

	// ---------------- Memory-unsafe C ----------------
	{
		ID: "MEM-001", Name: "gets()/strcpy()/strcat()/sprintf()", Category: CatMemory,
		Severity: SevCritical, Languages: []string{"c"},
		Pattern: re(`\b(gets|strcpy|strcat|sprintf|vsprintf|strtok)\s*\(`),
		Message: "Unbounded string functions that overflow buffers when input is longer than the destination.",
		Fix:     "Use bounds-checked variants (fgets, strlcpy, strlcat, snprintf) with explicit sizes.",
	},
	{
		ID: "MEM-002", Name: "unchecked scanf", Category: CatMemory,
		Severity: SevHigh, Languages: []string{"c"},
		Pattern: re(`\bscanf\s*\([^)]*%s`),
		Message: "scanf with %s reads unbounded input into a fixed buffer.",
		Fix:     "Use fgets with a size limit, or scanf with a field width like %127s.",
	},
	{
		ID: "MEM-003", Name: "manual memory copy", Category: CatMemory,
		Severity: SevHigh, Languages: []string{"c"},
		Pattern: re(`\bmemcpy\s*\([^)]*\)`),
		Message: "memcpy with mismatched sizes is a classic overflow source.",
		Fix:     "Validate source length against destination capacity before copying; prefer memcpy_s / checked helpers.",
	},
	{
		ID: "MEM-004", Name: "printf with variable format", Category: CatMemory,
		Severity: SevHigh, Languages: []string{"c"},
		Pattern: re(`printf\s*\(\s*[A-Za-z_][A-Za-z0-9_]*\s*\)`),
		Message: "Format string is a runtime variable; attacker-controlled text can become a format-string read/write bug.",
		Fix:     "Always pass a literal format string: printf(\"%s\", userdata) instead of printf(userdata).",
	},

	// ---------------- Insecure random ----------------
	{
		ID: "RND-001", Name: "non-cryptographic RNG for security", Category: CatRandom,
		Severity: SevMedium, Languages: []string{"generic"},
		Pattern: re(`(?i)\b(random\.(random|randint|choice|shuffle)|Math\.random\(\)|rand\(\)|time\.Now\(\).*rand|SecureRandom)`),
		Message: "Deterministic/predictable randomness used in a context that may involve tokens or secrets.",
		Fix:     "Use a cryptographically secure RNG: os.urandom, secrets, crypto/rand, SecureRandom, openssl_random_pseudo_bytes.",
	},

	// ---------------- XSS-ish sinks ----------------
	{
		ID: "XSS-001", Name: "innerHTML sink", Category: CatInjection,
		Severity: SevHigh, Languages: []string{"javascript"},
		Pattern: re(`\.innerHTML\s*=|document\.write\s*\(|dangerouslySetInnerHTML\s*=`),
		Message: "Assignment of dynamic content into HTML without escaping enables XSS.",
		Fix:     "Use textContent or a framework's safe rendering; escape before inserting untrusted HTML.",
	},

	// ---------------- SSRF-ish sinks ----------------
	{
		ID: "SSRF-001", Name: "outbound request with user-controlled URL", Category: CatSSRF,
		Severity: SevMedium, Languages: []string{"python", "javascript", "go", "java", "php"},
		Pattern: re(`(?i)(requests\.(get|post|request)|fetch\s*\(|http\.(Get|Post|NewRequest)|URLConnection|curl_|HttpClient)\s*\([^)]*\b(url|uri|input|request|host|param)\b`),
		Message: "An outbound HTTP request is built from a user-supplied URL, which may target internal services.",
		Fix:     "Resolve the URL, block private/loopback ranges, and validate the scheme and host against an allowlist.",
	},
}

// rulesFor returns the rules that apply to the given language list,
// plus any generic rules.
func rulesFor(languages []string) []*Rule {
	out := make([]*Rule, 0)
	langSet := map[string]bool{}
	for _, l := range languages {
		langSet[l] = true
	}
	for _, r := range allRules {
		for _, rl := range r.Languages {
			if rl == "generic" || langSet[rl] {
				out = append(out, r)
				break
			}
		}
	}
	return out
}
