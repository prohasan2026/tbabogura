const fs = require('fs');
const vm = require('vm');

const html = fs.readFileSync('admin.html', 'utf8');

// 1. Verify CSS in admin.html
console.log('--- VERIFYING ADMIT CARD PRINT CSS IN ADMIN.HTML ---');
const requiredCssRules = [
    'size: A4 portrait',
    'margin: 8mm 10mm 8mm 10mm !important',
    '#admitCardPrintArea',
    '.admit-card-wrapper',
    'border: 3px double #1e3a8a !important',
    'height: calc(297mm - 18mm) !important',
    '.instructions-block',
    '.signature-footer'
];

for (const rule of requiredCssRules) {
    if (!html.includes(rule)) {
        throw new Error(`Missing required CSS rule in admin.html: ${rule}`);
    }
}
console.log('✓ All required Print CSS rules found in admin.html!');

// 2. Extract script #4
let regex = /<script(?:\s+[^>]*)?>([\s\S]*?)<\/script>/gi;
let match;
let script4 = '';
let i = 0;
while ((match = regex.exec(html)) !== null) {
    i++;
    if (i === 4) {
        script4 = match[1];
        break;
    }
}

const elements = {};
function getMockEl(id) {
    if (!elements[id]) {
        elements[id] = {
            id: id,
            value: '',
            textContent: '',
            innerHTML: '',
            children: [],
            classList: {
                classes: new Set(),
                add: function(c) { this.classes.add(c); },
                remove: function(c) { this.classes.delete(c); },
                contains: function(c) { return this.classes.has(c); }
            },
            appendChild: function(child) { this.children.push(child); },
            focus: () => {},
            select: () => {}
        };
    }
    return elements[id];
}

let printedHTML = null;
const context = {
    window: {
        addEventListener: () => {},
        location: { hash: '' },
        print: () => { printedHTML = elements['printable-admit-card']?.innerHTML; }
    },
    addEventListener: () => {},
    document: {
        addEventListener: () => {},
        head: { appendChild: () => {} },
        body: { classList: { add: () => {}, remove: () => {} } },
        getElementById: (id) => getMockEl(id),
        createElement: (tag) => ({
            tagName: tag,
            value: '',
            textContent: '',
            innerHTML: '',
            selected: false,
            setAttribute: () => {},
            getAttribute: () => '',
            style: {},
            classList: { add: () => {}, remove: () => {}, contains: () => false },
            appendChild: () => {}
        }),
        querySelectorAll: () => []
    },
    localStorage: {
        data: {},
        getItem: function(k) { return this.data[k] || null; },
        setItem: function(k, v) { this.data[k] = v; }
    },
    sessionStorage: {
        getItem: () => null,
        setItem: () => {}
    },
    alert: (msg) => console.log('MOCK ALERT:', msg),
    confirm: () => true,
    prompt: () => '1000',
    console: console,
    setTimeout: (fn) => fn(),
    clearTimeout: () => {},
    setInterval: () => {},
    clearInterval: () => {},
    fetch: () => Promise.resolve({ json: () => Promise.resolve({ status: 'success' }) }),
    buildGradeSelectHTML: () => '',
    print: () => { printedHTML = elements['printable-admit-card']?.innerHTML; }
};

context.window = context;
vm.createContext(context);
vm.runInContext(script4, context);

console.log('--- TESTING ADMIT CARD ROLL DESYNC PREVENTION & PRINT FIT ---');

// Setup mock candidate with Roll 1003
const studentObj = {
    uniqueId: 'TBA-8001',
    name: 'Rahim Ahmed',
    studentName: 'Rahim Ahmed',
    bengaliName: 'রহিম আহমেদ',
    fatherEnglish: 'Karim Ahmed',
    motherEnglish: 'Rahima Begum',
    examCenter: 'Kahalu',
    center: 'Kahalu',
    class: 'Class 8',
    studentClass: 'Class 8',
    schoolEnglish: 'Kahalu High School',
    roll: '1003',
    rollNo: '1003',
    assignedRoll: '1003',
    rollNumber: '1003',
    studentRoll: '1003',
    status: 'Verified',
    paymentStatus: 'Verified'
};

context.window.allStudents = [JSON.parse(JSON.stringify(studentObj))];
context.window.allMasterData = [JSON.parse(JSON.stringify(studentObj))];
context.window.rawAdmitStudents = [JSON.parse(JSON.stringify(studentObj))];
context.window.currentAdmitStudents = [JSON.parse(JSON.stringify(studentObj))];

// 1. Initial State: Should render Roll 1003
const initialSlip = context.buildAdmitSlipHTML(studentObj);
if (!initialSlip.includes('1003')) {
    throw new Error('Initial admit slip did not contain Roll 1003!');
}
if (!initialSlip.includes('admit-card-container') || !initialSlip.includes('instructions-block') || !initialSlip.includes('signature-footer')) {
    throw new Error('Admit slip missing critical single-page layout classes!');
}
console.log('✓ Initial admit slip generated with Roll 1003 and proper single-page classes.');

// 2. Execute Roll Reset
console.log('\n--- EXECUTING ROLL RESET ---');
context.executeDirectRollReset('ALL', 'ALL');

// Check live roll function
const liveRollAfterReset = context.getLiveStudentRoll(studentObj);
if (liveRollAfterReset !== '') {
    throw new Error(`Expected getLiveStudentRoll to return empty string, got: ${liveRollAfterReset}`);
}
console.log('✓ getLiveStudentRoll returned empty string after reset.');

// 3. Render Admit Slip after reset - Must NOT display 1003, MUST display "অপেক্ষমাণ / বরাদ্দ হয়নি"
const resetSlip = context.buildAdmitSlipHTML(studentObj);
if (resetSlip.includes('1003')) {
    throw new Error('CRITICAL BUG: Admit slip STILL displays old roll 1003 after reset!');
}
if (!resetSlip.includes('অপেক্ষমাণ / বরাদ্দ হয়নি')) {
    throw new Error('Admit slip did not display "অপেক্ষমাণ / বরাদ্দ হয়নি" for reset roll!');
}
console.log('✓ Desync fixed: Admit slip immediately reflects reset roll and displays "অপেক্ষমাণ / বরাদ্দ হয়নি"!');

// 4. Test Single Admit Card Print
context.printSingleAdmitCard('TBA-8001');
if (!printedHTML || !printedHTML.includes('অপেক্ষমাণ / বরাদ্দ হয়নি')) {
    throw new Error('Printed admit card HTML did not reflect the reset status!');
}
console.log('✓ printSingleAdmitCard printed slip with unassigned roll warning / pending badge!');

// 5. Test Table Row Rendering
const tbodyMock = getMockEl('test-tbody');
context.renderAdmitCardTableRows(tbodyMock, context.window.currentAdmitStudents);
const rowHtml = tbodyMock.children[0]?.innerHTML || '';
if (!rowHtml.includes('অপেক্ষমাণ')) {
    throw new Error('Admit cards table did not render "অপেক্ষমাণ" badge for reset student!');
}
console.log('✓ Admit cards management table rendered "অপেক্ষমাণ" badge instead of old roll.');

console.log('\n=============================================');
console.log('ADMIT CARD PRINT & DESYNC SUITE PASSED 100%!');
console.log('=============================================');
