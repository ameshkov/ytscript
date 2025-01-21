import { FilterListParser } from '@adguard/agtree';
import { scriptlets } from '@adguard/scriptlets';

async function main() {
    // STEP 1: Download the AdGuard filter rules
    const response = await fetch('https://filters.adtidy.org/extension/chromium/filters/2.txt');
    if (!response.ok) {
        throw new Error(`Failed to fetch filter list: HTTP ${response.status}`);
    }
    const filterText = await response.text();

    // STEP 2: Parse rules with AGTree
    // parse(...) returns a FilterTree object that provides various ways to iterate over rules
    const tree = FilterListParser.parse(filterText);

    // We'll gather converted scripts here
    const finalScripts = [];

    // STEP 3: Iterate over all rules
    for (const rule of tree.children) {
        if (rule.type !== 'ScriptletInjectionRule' && rule.type !== 'JsInjectionRule') {
            continue
        }

        // Check if it has a domain restriction that includes youtube
        const domains = (rule.domains?.children || []).filter((domain) => domain.exception === false);
        const hasYoutube = domains.some((domain) => {
            return (domain.value === 'youtube.com' || domain.value.endsWith('.youtube.com'));
        })

        if (!hasYoutube) {
            continue;
        }

        const domainsList = domains.map((domain) => `'${domain.value}'`);
        const ruleScript = getRuleScript(rule);

        const finalScript = `// From rule: ${rule.raws.text}
if ([${domainsList.join(', ')}].includes(window.location.hostname)) {
    ${ruleScript}
}
`;

        finalScripts.push(finalScript);
    }

    // STEP 4: Combine all the JS code into one string
    const combinedJs = finalScripts.join('\n');

    // For demonstration, print to stdout
    // You could also write to a file, serve via API, etc.
    console.log(combinedJs);
}

// Extracts rule script from the rule.
function getRuleScript(rule) {
    if (rule.type === 'ScriptletInjectionRule') {
        const params = rule.body.children[0].children;

        const scriptletSource = {
            name: unquote(params[0].value),
            args: params.slice(1).map(p => unquote(p.value)),
            engine: 'extension',
            version: '1.0',
            verbose: false
        }

        const code = scriptlets.invoke(scriptletSource);

        return code;
    } else if (rule.type === 'JsInjectionRule') {
        const code = rule.body.value;

        return code;
    } else {
        throw new Error(`Unsupported rule type ${rule.type}`);
    }
}

function unquote(str) {
    return str.replace(/^['"]|['"]$/g, '');
}

// Run
main().catch((err) => {
    console.error(err);
    process.exit(1);
});
