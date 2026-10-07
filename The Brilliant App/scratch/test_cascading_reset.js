
const fs = require('fs');
const vm = require('vm');

const html = fs.readFileSync('admin.html', 'utf8');

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

// Setup a mock DOM environment
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

const context = {
    window: {
        addEventListener: () => {},
        location: { hash: '' },
        buildGradeSelectHTML: () => ''
    },
    addEventListener: () => {},
    document: {
        addEventListener: () => {},
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
    buildGradeSelectHTML: () => ''
};

context.window = context;

vm.createContext(context);
vm.runInContext(script4, context);

console.log('--- TESTING CASCADING FILTER & RESET ENGINE ---');

// 1. Populate test dataset
const mockStudents = [
    { uniqueId: 'TBA-101', nameEnglish: 'Student A1', examCenter: 'Kahalu', center: 'Kahalu', class: 'Class 5', roll: '2001', rollNo: '2001', status: 'Verified', paymentStatus: 'Verified' },
    { uniqueId: 'TBA-102', nameEnglish: 'Student A2', examCenter: 'Kahalu', center: 'Kahalu', class: 'Class 8', roll: '2002', rollNo: '2002', status: 'Verified', paymentStatus: 'Verified' },
    { uniqueId: 'TBA-103', nameEnglish: 'Student A3', examCenter: 'Kahalu', center: 'Kahalu', class: 'Class 4', roll: '2003', rollNo: '2003', status: 'Verified', paymentStatus: 'Verified' },
    { uniqueId: 'TBA-104', nameEnglish: 'Student B1', examCenter: 'Adamdighi', center: 'Adamdighi', class: 'Class 6', roll: '1001', rollNo: '1001', status: 'Verified', paymentStatus: 'Verified' },
    { uniqueId: 'TBA-105', nameEnglish: 'Student B2', examCenter: 'Adamdighi', center: 'Adamdighi', class: 'Class 9', roll: '1002', rollNo: '1002', status: 'Verified', paymentStatus: 'Verified' },
    { uniqueId: 'TBA-106', nameEnglish: 'Student C1', examCenter: 'Kahalu', center: 'Kahalu', class: 'Class 8', roll: '', rollNo: '', status: 'Pending', paymentStatus: 'Pending' } // unverified
];

vm.runInContext("allStudents.length = 0; allMasterData.length = 0;", context);
mockStudents.forEach(s => {
    context.window.allStudents.push(s);
    context.window.allMasterData.push(s);
});

// Test 1: Test updateDynamicClassDropdown for Kahalu
const kahaluCenterSelect = getMockEl('test-center-kahalu');
kahaluCenterSelect.value = 'Kahalu';
const kahaluClassSelect = getMockEl('test-class-kahalu');

context.updateDynamicClassDropdown('test-center-kahalu', 'test-class-kahalu');
console.log('Kahalu class options count:', kahaluClassSelect.children.length);
const kahaluClasses = kahaluClassSelect.children.map(c => c.value);
console.log('Kahalu classes extracted & sorted:', kahaluClasses);

// Verified classes in Kahalu: Class 4, Class 5, Class 8 (Class 4 has weight 4, Class 5 has 5, Class 8 has 8)
if (kahaluClasses.length !== 3) throw new Error('Expected 3 unique classes for Kahalu, got ' + kahaluClasses.length);
if (kahaluClasses[0] !== 'Class 4' || kahaluClasses[1] !== 'Class 5' || kahaluClasses[2] !== 'Class 8') {
    throw new Error('Incorrect hierarchy sort for Kahalu classes: ' + JSON.stringify(kahaluClasses));
}
console.log('✓ Dynamic class dropdown populated & sorted hierarchically for Kahalu!');

// Test 2: Test updateDynamicClassDropdown for Adamdighi
const adamCenterSelect = getMockEl('test-center-adam');
adamCenterSelect.value = 'Adamdighi';
const adamClassSelect = getMockEl('test-class-adam');

context.updateDynamicClassDropdown('test-center-adam', 'test-class-adam');
const adamClasses = adamClassSelect.children.map(c => c.value);
console.log('Adamdighi classes extracted & sorted:', adamClasses);
if (adamClasses.length !== 2 || adamClasses[0] !== 'Class 6' || adamClasses[1] !== 'Class 9') {
    throw new Error('Incorrect hierarchy sort for Adamdighi classes: ' + JSON.stringify(adamClasses));
}
console.log('✓ Dynamic class dropdown populated & sorted for Adamdighi!');

// Test 3: Test updateDynamicClassDropdown for ALL centers
const allCenterSelect = getMockEl('test-center-all');
allCenterSelect.value = 'ALL';
const allClassSelect = getMockEl('test-class-all');
context.updateDynamicClassDropdown('test-center-all', 'test-class-all');
const allClasses = allClassSelect.children.map(c => c.value);
console.log('ALL centers classes extracted & sorted:', allClasses);
if (allClasses.length !== 5 || allClasses[0] !== 'Class 4' || allClasses[4] !== 'Class 9') {
    throw new Error('Incorrect hierarchy sort for ALL centers classes: ' + JSON.stringify(allClasses));
}
console.log('✓ Dynamic class dropdown populated & sorted for ALL centers!');

(async () => {
    // Test 4: Test executeResetRolls for specific center (Kahalu) and specific class (Class 8)
    console.log('\n--- TESTING TARGETED RESET ROLLS ---');
    // Student A2 is Kahalu Class 8 with Roll 2002
    console.log('Before reset: Student A2 (Kahalu, Class 8) roll =', mockStudents[1].roll);
    await context.executeResetRolls('Kahalu', 'Class 8');

    console.log('After reset: Student A2 roll =', mockStudents[1].roll);
    if (mockStudents[1].roll !== '' || mockStudents[1].rollNo !== '') {
        throw new Error('Student A2 roll was not reset!');
    }
    // Check that other students in Kahalu (e.g. Student A1 Class 5) were NOT reset
    if (mockStudents[0].roll !== '2001') {
        throw new Error('Student A1 roll was accidentally reset!');
    }
    console.log('✓ Targeted Reset Rolls for Kahalu Class 8 succeeded without touching other classes!');

    // Test 5: Test executeResetRolls for entire Kahalu center
    await context.executeResetRolls('Kahalu', 'ALL');
    if (mockStudents[0].roll !== '' || mockStudents[2].roll !== '') {
        throw new Error('Kahalu students rolls were not cleared!');
    }
    // Adamdighi students must still have rolls
    if (mockStudents[3].roll !== '1001' || mockStudents[4].roll !== '1002') {
        throw new Error('Adamdighi students rolls were accidentally cleared!');
    }
    console.log('✓ Center-wide Reset Rolls for Kahalu succeeded without touching Adamdighi!');

    // Test 6: Test executeResetRolls for ALL centers
    await context.executeResetRolls('ALL', 'ALL');
    if (mockStudents[3].roll !== '' || mockStudents[4].roll !== '') {
        throw new Error('Adamdighi students rolls were not cleared on full reset!');
    }
    console.log('✓ Full Reset Rolls for ALL centers succeeded!');

    // Verify localStorage was updated
    const savedStudents = JSON.parse(context.localStorage.getItem('tba_students'));
    const anyRollRemaining = savedStudents.some(s => s.roll || s.rollNo || s.rollNumber);
    if (anyRollRemaining) {
        throw new Error('localStorage still contains students with rolls!');
    }
    console.log('✓ localStorage persistence verified clean!');

    console.log('\n=============================================');
    console.log('ALL CASCADING FILTER & RESET TESTS PASSED 100%!');
    console.log('=============================================');
})();