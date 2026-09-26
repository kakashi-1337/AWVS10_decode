/**
 * ANBU Mutation Engine
 * Configurable mutation strategies for runtime variable fuzzing
 * 
 * Mutation types:
 * - Boolean flip
 * - Integer boundary (0, -1, MAX_SAFE_INTEGER, overflow)
 * - String swap (empty, long, format string, prototype pollution)
 * - Array manipulation (empty, extra elements, type confusion)
 * - Object property injection (__proto__, constructor)
 * - ID swap (swap resource IDs for IDOR/authorization bypass)
 * - Custom expression (target-specific mutations)
 */

class MutationEngine {
    constructor() {
        this.rules = [];
        this.builtinStrategies = this.getBuiltinStrategies();
    }

    /**
     * Load mutation rules from profile
     */
    loadRules(rules) {
        this.rules = rules;
    }

    /**
     * Get the appropriate mutation for a variable based on rules
     */
    getMutation(varInfo) {
        // Check profile-specific rules first
        for (const rule of this.rules) {
            if (this.ruleMatches(rule, varInfo)) {
                return {
                    name: rule.name,
                    expression: (v) => rule.expression(v)
                };
            }
        }

        // Fall back to type-based builtin strategies
        const strategy = this.builtinStrategies[varInfo.type];
        if (strategy) {
            return {
                name: `builtin_${varInfo.type}`,
                expression: (v) => strategy(v)
            };
        }

        return null;
    }

    /**
     * Check if a rule matches a variable
     */
    ruleMatches(rule, varInfo) {
        if (rule.variableName && rule.variableName !== varInfo.name) return false;
        if (rule.variablePattern && !varInfo.name.match(new RegExp(rule.variablePattern, 'i'))) return false;
        if (rule.type && rule.type !== varInfo.type) return false;
        return true;
    }

    /**
     * Built-in mutation strategies by type
     */
    getBuiltinStrategies() {
        return {
            'boolean': (v) => `${v.name} = ${!v.value}`,
            
            'number': (v) => {
                const mutations = [
                    `${v.name} = 0`,
                    `${v.name} = -1`,
                    `${v.name} = ${Number.MAX_SAFE_INTEGER}`,
                    `${v.name} = ${v.value + 1}`, // Off by one
                    `${v.name} = NaN`
                ];
                return mutations[Math.floor(Math.random() * mutations.length)];
            },
            
            'string': (v) => {
                const mutations = [
                    `${v.name} = ""`,
                    `${v.name} = "${v.value}".repeat(1000)`,
                    `${v.name} = "{{7*7}}"`, // SSTI probe
                    `${v.name} = "${v.value}\\x00injected"`, // Null byte
                ];
                return mutations[Math.floor(Math.random() * mutations.length)];
            },
            
            'object': (v) => {
                // Prototype pollution probe
                return `Object.assign(${v.name}, {"__proto__": {"polluted": true}})`;
            }
        };
    }
}

// Pre-built mutation rule sets for common bug classes
const MUTATION_PRESETS = {
    
    // IDOR / Authorization bypass
    idor: [
        {
            name: 'id_swap',
            variablePattern: '(id|Id|ID|identifier|uuid|uid)',
            type: 'string',
            expression: (v) => {
                // Swap last character to test IDOR
                const val = v.value || '';
                const swapped = val.slice(0, -1) + (val.slice(-1) === '0' ? '1' : '0');
                return `${v.name} = "${swapped}"`;
            }
        }
    ],
    
    // Boolean privilege escalation
    privilege: [
        {
            name: 'role_flip',
            variablePattern: '(admin|role|priv|auth|allow|enabled|active|verified|confirmed)',
            type: 'boolean',
            expression: (v) => `${v.name} = true`
        },
        {
            name: 'status_override',
            variablePattern: '(status|state|phase|step)',
            type: 'string',
            expression: (v) => `${v.name} = "CONFIRMED"` // Force state transition
        }
    ],

    // Price / quantity manipulation
    financial: [
        {
            name: 'price_zero',
            variablePattern: '(price|amount|total|cost|fee|balance|quantity|qty)',
            type: 'number',
            expression: (v) => `${v.name} = 0`
        },
        {
            name: 'price_negative',
            variablePattern: '(price|amount|total|cost|fee)',
            type: 'number',
            expression: (v) => `${v.name} = -${v.value || 1}`
        }
    ],

    // E-voting specific
    evoting: [
        {
            name: 'vote_swap',
            variablePattern: '(selectedActual|votingOption|chosen|answer|candidate)',
            expression: (v) => {
                // Generic vote swap — swaps first/second element if array
                if (v.type === 'object' && v.subtype === 'array') {
                    return `(() => { const tmp = ${v.name}[0]; ${v.name}[0] = ${v.name}[1]; ${v.name}[1] = tmp; return ${v.name}; })()`;
                }
                return `${v.name}`; // No-op for non-arrays
            }
        },
        {
            name: 'return_code_forge',
            variablePattern: '(shortChoice|returnCode|choiceReturn)',
            expression: (v) => {
                // Replace return codes with predictable values
                return `${v.name} = ${v.name}.map(() => "FORGED")`;
            }
        },
        {
            name: 'key_swap',
            variablePattern: '(publicKey|electionPublicKey|encryptionKey|pk_)',
            expression: (v) => {
                // Log the key value for analysis (don't mutate — would break ZKPs)
                return `(() => { console.log("ANBU_KEY_CAPTURE:", JSON.stringify(${v.name})); return ${v.name}; })()`;
            }
        }
    ]
};

module.exports = { MutationEngine, MUTATION_PRESETS };
