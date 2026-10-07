const fs = require('fs');
const vm = require('vm');

console.log('--- TESTING ADMIT-CARD.HTML FULL-WIDTH A4 PRINT LAYOUT ---');

const html = fs.readFileSync('admit-card.html', 'utf8');

// 1. Verify Print CSS
const requiredCssRules = [
    'size: A4 portrait',
    'margin: 8mm 10mm 8mm 10mm !important',
    '#admitCardPrintArea',
    '.admit-card-wrapper',
    '.admit-card-container',
    'border: 3px double #1e3a8a !important',
    'height: calc(297mm - 18mm) !important',
    '-webkit-print-color-adjust: exact !important',
    'print-color-adjust: exact !important',
    'color-adjust: exact !important',
    '.instructions-block',
    '.signature-footer'
];

for (const rule of requiredCssRules) {
    if (!html.includes(rule)) {
        throw new Error(`Missing required CSS rule in admit-card.html: ${rule}`);
    }
}
console.log('✓ All 12 required Print CSS rules found in admit-card.html!');

// 2. Extract script
let regex = /<script(?:\s+[^>]*)?>([\s\S]*?)<\/script>/gi;
let match;
let script = '';
let count = 0;
while ((match = regex.exec(html)) !== null) {
    count++;
    if (count === 3) { // the main inline script in admit-card.html
        script = match[1];
        break;
    }
}

const context = {
    addEventListener: () => {},
    window: {
        addEventListener: () => {},
        location: { search: '' },
        print: () => {}
    },
    document: {
        getElementById: () => ({
            value: '',
            classList: { add: () => {}, remove: () => {} },
            innerHTML: '',
            scrollIntoView: () => {}
        }),
        addEventListener: () => {}
    },
    localStorage: {
        getItem: () => null,
        setItem: () => {}
    },
    console: console,
    alert: (msg) => console.log('ALERT:', msg),
    confirm: () => true
};

context.window = context;
vm.createContext(context);
vm.runInContext(script, context);

// Test candidate rendering
const student = {
    uniqueId: 'TBA-9999',
    name: 'Sumaiya Akter',
    studentName: 'Sumaiya Akter',
    bengaliName: 'সুমাইয়া আক্তার',
    fatherEnglish: 'Rafiqul Islam',
    motherEnglish: 'Salma Begum',
    class: 'Class 5',
    institutionType: 'Madrasah',
    schoolEnglish: 'Bogura Central Madrasah',
    center: 'Adamdighi',
    roll: '5001'
};

const renderedSlip = context.buildAdmitSlipHTML(student);

// Check wrapper
if (!renderedSlip.includes('id="admitCardPrintArea"')) {
    throw new Error('Rendered slip missing id="admitCardPrintArea"');
}
if (!renderedSlip.includes('admit-card-wrapper') || !renderedSlip.includes('admit-card-container')) {
    throw new Error('Rendered slip missing admit-card-wrapper/admit-card-container classes');
}
if (!renderedSlip.includes('border: 3px double #1e3a8a')) {
    throw new Error('Rendered slip missing 3px double royal blue border');
}
if (!renderedSlip.includes('5001')) {
    throw new Error('Rendered slip missing roll 5001');
}
if (!renderedSlip.includes('TBA-9999')) {
    throw new Error('Rendered slip missing reg no TBA-9999');
}
if (!renderedSlip.includes('OFFICIAL SEAL')) {
    throw new Error('Rendered slip missing official seal');
}

console.log('✓ buildAdmitSlipHTML rendered full-width card with Royal Blue theme and accurate data bindings!');

// Check empty roll behavior
const studentNoRoll = { ...student, roll: '', rollNo: '' };
const renderedNoRoll = context.buildAdmitSlipHTML(studentNoRoll);
if (!renderedNoRoll.includes('অপেক্ষমাণ / বরাদ্দ হয়নি')) {
    throw new Error('Rendered slip for student without roll missing "অপেক্ষমাণ / বরাদ্দ হয়নি" badge');
}
console.log('✓ Student with unallocated roll properly renders "অপেক্ষমাণ / বরাদ্দ হয়নি" badge!');

console.log('\n=============================================');
console.log('ADMIT-CARD.HTML FULL-WIDTH SUITE PASSED 100%!');
console.log('=============================================');
