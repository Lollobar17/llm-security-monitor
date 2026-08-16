// Package registry provides the special token database used by the STI detector.
//
// Tokens are classified by architecture (ChatML, LLaMA, Qwen/DeepSeek, …)
// and risk level (High → role escalation / tool hijack, Medium → boundary
// injection, Low → informational / noise).
//
// Reference: https://blog.sentry.security/special-token-injection-sti-attack-guide/
package registry

import "strings"

// RiskLevel describes how dangerous a token is when found in user-controlled content.
type RiskLevel int

const (
	RiskLow    RiskLevel = iota // Informational; context-dependent danger
	RiskMedium                  // Boundary injection; degrades conversation structure
	RiskHigh                    // Role escalation / function call hijacking — block-worthy
)

func (r RiskLevel) String() string {
	switch r {
	case RiskHigh:
		return "HIGH"
	case RiskMedium:
		return "MEDIUM"
	default:
		return "LOW"
	}
}

// Token describes a single special token entry.
type Token struct {
	Value        string
	Name         string
	Architecture string
	Risk         RiskLevel
	Description  string
}

// Registry is the full list of known special tokens.
var Registry = []Token{

	// ── ChatML (OpenAI GPT, Qwen, OpenChat) ──────────────────────────────────
	{
		Value: "<|im_start|>system", Name: "System Role Injection (ChatML)",
		Architecture: "ChatML / GPT / Qwen", Risk: RiskHigh,
		Description: "Opens a system-level instruction block — full role escalation",
	},
	{
		Value: "<|im_start|>assistant", Name: "Assistant Role Injection (ChatML)",
		Architecture: "ChatML / GPT / Qwen", Risk: RiskHigh,
		Description: "Injects a fake assistant response to shift conversation state",
	},
	{
		Value: "<|im_start|>", Name: "Message Block Start (ChatML)",
		Architecture: "ChatML / GPT / Qwen", Risk: RiskMedium,
		Description: "Opens a new message block; role unspecified but structure broken",
	},
	{
		Value: "<|im_end|>", Name: "Message Block End (ChatML)",
		Architecture: "ChatML / GPT / Qwen", Risk: RiskMedium,
		Description: "Prematurely closes the current message block",
	},
	{
		Value: "<|endoftext|>", Name: "End-of-Text (GPT)",
		Architecture: "ChatML / GPT", Risk: RiskMedium,
		Description: "Forces generation cutoff; can terminate system prompt early",
	},
	{
		Value: "<|endofprompt|>", Name: "End-of-Prompt",
		Architecture: "ChatML", Risk: RiskMedium,
		Description: "Marks end of prompt input section",
	},

	// ── Function / Tool Calling ───────────────────────────────────────────────
	{
		Value: "<tool_call>", Name: "Tool Call Start (Qwen/DeepSeek)",
		Architecture: "Qwen / DeepSeek / Mistral", Risk: RiskHigh,
		Description: "Initiates a function/tool call — direct function call hijacking",
	},
	{
		Value: "</tool_call>", Name: "Tool Call End",
		Architecture: "Qwen / DeepSeek", Risk: RiskMedium,
		Description: "Closes tool call wrapper; part of hijack payload",
	},
	{
		Value: "<tool_response>", Name: "Tool Response Start",
		Architecture: "Qwen / DeepSeek", Risk: RiskHigh,
		Description: "Injects a fake tool response, poisoning the reasoning context",
	},
	{
		Value: "</tool_response>", Name: "Tool Response End",
		Architecture: "Qwen / DeepSeek", Risk: RiskMedium,
		Description: "Closes tool response wrapper",
	},
	{
		Value: "<tools>", Name: "Tool Definitions Start",
		Architecture: "Qwen / DeepSeek", Risk: RiskHigh,
		Description: "Wraps function definitions; allows injecting fake tool schemas",
	},
	{
		Value: "</tools>", Name: "Tool Definitions End",
		Architecture: "Qwen / DeepSeek", Risk: RiskMedium,
		Description: "Closes function definition block",
	},
	{
		Value: "<|function_call|>", Name: "Function Call (ChatML variant)",
		Architecture: "ChatML variant", Risk: RiskHigh,
		Description: "Signals function invocation in ChatML-style function-calling models",
	},
	{
		Value: "<|tool|>", Name: "Tool Role (ChatML)",
		Architecture: "ChatML", Risk: RiskHigh,
		Description: "Marks tool output — can inject fake tool results",
	},
	{
		Value: "<|tool_response|>", Name: "Tool Response (ChatML)",
		Architecture: "ChatML", Risk: RiskHigh,
		Description: "Tool response injection via ChatML role token",
	},

	// ── LLaMA / Alpaca ────────────────────────────────────────────────────────
	{
		Value: "[INST]", Name: "Instruction Start (LLaMA-2)",
		Architecture: "LLaMA / Alpaca / Mistral", Risk: RiskHigh,
		Description: "Starts instruction block; injecting this overrides system behavior",
	},
	{
		Value: "[/INST]", Name: "Instruction End (LLaMA-2)",
		Architecture: "LLaMA / Alpaca / Mistral", Risk: RiskMedium,
		Description: "Closes instruction section, enabling further injection",
	},
	{
		Value: "<<SYS>>", Name: "System Prompt Start (LLaMA-2)",
		Architecture: "LLaMA / Alpaca", Risk: RiskHigh,
		Description: "Opens system instruction block — highest-privilege role injection",
	},
	{
		Value: "<</SYS>>", Name: "System Prompt End (LLaMA-2)",
		Architecture: "LLaMA / Alpaca", Risk: RiskMedium,
		Description: "Closes system instruction block",
	},
	{
		Value: "<s>", Name: "Start of Sequence",
		Architecture: "LLaMA / BERT", Risk: RiskMedium,
		Description: "Sequence start; restarting a sequence can reset context",
	},
	{
		Value: "</s>", Name: "End of Sequence",
		Architecture: "LLaMA / BERT", Risk: RiskMedium,
		Description: "Sequence end; premature termination of context",
	},

	// ── DeepSeek / Qwen Thinking ──────────────────────────────────────────────
	{
		Value: "<think>", Name: "Reasoning Block Start (DeepSeek-R1 / Qwen3)",
		Architecture: "DeepSeek / Qwen", Risk: RiskLow,
		Description: "Initiates internal reasoning; may expose chain-of-thought",
	},
	{
		Value: "</think>", Name: "Reasoning Block End",
		Architecture: "DeepSeek / Qwen", Risk: RiskLow,
		Description: "Closes reasoning block",
	},
	{
		Value: "/system_override", Name: "System Override Directive",
		Architecture: "Custom / fine-tuned", Risk: RiskHigh,
		Description: "Jinja-level override directive seen in custom fine-tuning templates",
	},
	{
		Value: "/no_think", Name: "Thinking Suppression",
		Architecture: "Qwen-thinking", Risk: RiskMedium,
		Description: "Disables chain-of-thought reasoning",
	},

	// ── Fill-in-the-Middle ────────────────────────────────────────────────────
	{
		Value: "<fim_prefix|>", Name: "FIM Prefix",
		Architecture: "StarCoder / Code models", Risk: RiskLow,
		Description: "Fill-in-the-Middle prefix token",
	},
	{
		Value: "<fim_middle|>", Name: "FIM Middle",
		Architecture: "StarCoder / Code models", Risk: RiskLow,
		Description: "FIM insertion point marker",
	},
	{
		Value: "<fim_suffix|>", Name: "FIM Suffix",
		Architecture: "StarCoder / Code models", Risk: RiskLow,
		Description: "FIM suffix token",
	},

	// ── BERT-style ────────────────────────────────────────────────────────────
	{
		Value: "[MASK]", Name: "Masked Token (BERT)",
		Architecture: "BERT / RoBERTa", Risk: RiskLow,
		Description: "Masked language model token",
	},
	{
		Value: "[CLS]", Name: "Classification Token (BERT)",
		Architecture: "BERT", Risk: RiskLow,
		Description: "Classification task anchor token",
	},
	{
		Value: "[SEP]", Name: "Separator (BERT)",
		Architecture: "BERT", Risk: RiskLow,
		Description: "Segment separator; unexpected injection can split inputs",
	},
}

// ByRisk returns all tokens at the given risk level.
func ByRisk(r RiskLevel) []Token {
	var out []Token
	for _, t := range Registry {
		if t.Risk == r {
			out = append(out, t)
		}
	}
	return out
}

// ByArchitecture returns tokens whose Architecture field contains the given string.
func ByArchitecture(arch string) []Token {
	arch = strings.ToLower(arch)
	var out []Token
	for _, t := range Registry {
		if strings.Contains(strings.ToLower(t.Architecture), arch) {
			out = append(out, t)
		}
	}
	return out
}
