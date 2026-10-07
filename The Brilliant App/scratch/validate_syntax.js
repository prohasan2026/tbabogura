const fs = require('fs');
const vm = require('vm');

let errorCount = 0;

console.log('--- VALIDATING SYNTAX ---');

// 1. Validate Code.gs
try {
    const codeGs = fs.readFileSync('Code.gs', 'utf8');
    new vm.Script(codeGs, { filename: 'Code.gs' });
    console.log('✓ Code.gs parsed with 0 syntax errors.');
} catch (e) {
    console.error('❌ Syntax error in Code.gs:', e.message);
    errorCount++;
}

// 2. Validate admin.html scripts
try {
    const adminHtml = fs.readFileSync('admin.html', 'utf8');
    const regex = /<script(\s+[^>]*)?>([\s\S]*?)<\/script>/gi;
    let match;
    let scriptIndex = 0;
    while ((match = regex.exec(adminHtml)) !== null) {
        scriptIndex++;
        const attrs = match[1] || '';
        const content = match[2].trim();
        if (!content) continue;
        try {
            if (attrs.includes('type="module"')) {
                // Validate ES module syntax
                new vm.SourceTextModule(content, { identifier: `admin.html#script-${scriptIndex}` });
            } else {
                new vm.Script(content, { filename: `admin.html#script-${scriptIndex}` });
            }
            console.log(`✓ admin.html script tag #${scriptIndex} parsed successfully.`);
        } catch (scriptErr) {
            console.error(`❌ Syntax error in admin.html script tag #${scriptIndex}:`, scriptErr.message);
            errorCount++;
        }
    }
} catch (e) {
    console.error('❌ Error reading admin.html:', e.message);
    errorCount++;
}

// 3. Validate admit-card.html scripts
try {
    const admitCardHtml = fs.readFileSync('admit-card.html', 'utf8');
    const regex = /<script(\s+[^>]*)?>([\s\S]*?)<\/script>/gi;
    let match;
    let scriptIndex = 0;
    while ((match = regex.exec(admitCardHtml)) !== null) {
        scriptIndex++;
        const content = match[2].trim();
        if (!content) continue;
        try {
            new vm.Script(content, { filename: `admit-card.html#script-${scriptIndex}` });
            console.log(`✓ admit-card.html script tag #${scriptIndex} parsed successfully.`);
        } catch (scriptErr) {
            console.error(`❌ Syntax error in admit-card.html script tag #${scriptIndex}:`, scriptErr.message);
            errorCount++;
        }
    }
} catch (e) {
    console.error('❌ Error reading admit-card.html:', e.message);
    errorCount++;
}

if (errorCount === 0) {
    console.log('=============================================');
    console.log('ALL FILES SYNTAX VALIDATED: 0 ERRORS!');
    console.log('=============================================');
} else {
    process.exit(1);
}
