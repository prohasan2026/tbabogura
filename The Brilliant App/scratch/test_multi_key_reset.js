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
        location: { hash: '' }
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

console.log('--- RUNNING MULTI-KEY RESET SPECIFICATION TEST ---');

// Setup diverse students with different roll property keys and casing
const testStudents = [
    {
        uniqueId: 'ST-001',
        name: 'Student 1',
        examCenter: 'Kahalu',
        studentClass: 'Class 5',
        roll: '1001',
        rollNo: '1001',
        assignedRoll: '1001',
        rollNumber: '1001',
        studentRoll: '1001'
    },
    {
        id: 'ST-002',
        name: 'Student 2',
        center: 'kahalu', // lower case
        class: 'class 5',  // lower case
        roll: '1002',
        rollNo: '',
        assignedRoll: '1002'
    },
    {
        UniqueId: 'ST-003',
        name: 'Student 3',
        examCenter: 'Adamdighi',
        class: 'Class 6',
        roll: '2001',
        studentRoll: '2001'
    }
];

context.window.allStudents = JSON.parse(JSON.stringify(testStudents));
context.window.allMasterData = JSON.parse(JSON.stringify(testStudents));
context.allStudents = context.window.allStudents;
context.allMasterData = context.window.allMasterData;

// Execute reset for Kahalu / Class 5
context.executeDirectRollReset('Kahalu', 'Class 5');

// Check student 1 in allStudents
const s1 = context.window.allStudents[0];
if (s1.roll !== '' || s1.rollNo !== '' || s1.assignedRoll !== '' || s1.rollNumber !== '' || s1.studentRoll !== '') {
    throw new Error('ST-001 in allStudents still has roll properties!');
}

// Check student 1 in allMasterData
const m1 = context.window.allMasterData[0];
if (m1.roll !== '' || m1.rollNo !== '' || m1.assignedRoll !== '' || m1.rollNumber !== '' || m1.studentRoll !== '') {
    throw new Error('ST-001 in allMasterData still has roll properties!');
}

// Check student 2 (lowercase casing test)
const s2 = context.window.allStudents[1];
if (s2.roll !== '' || s2.assignedRoll !== '') {
    throw new Error('ST-002 (casing test) was not reset!');
}

// Check student 3 (Adamdighi - should remain untouched)
const s3 = context.window.allStudents[2];
if (s3.roll !== '2001' || s3.studentRoll !== '2001') {
    throw new Error('ST-003 in Adamdighi was mistakenly reset!');
}

// Verify localStorage
const localData = JSON.parse(context.localStorage.getItem('tba_students'));
if (localData[0].roll !== '' || localData[1].roll !== '' || localData[2].roll !== '2001') {
    throw new Error('localStorage tba_students verification failed!');
}

console.log('✓ Multi-key reset verified across all properties (roll, rollNo, assignedRoll, rollNumber, studentRoll)!');
console.log('✓ Dual array sync (allStudents & allMasterData) verified!');
console.log('✓ Case-insensitive and alias key matching (center/examCenter, class/studentClass) verified!');
console.log('✓ Targeted isolation verified (Adamdighi student untouched)!');
console.log('✓ LocalStorage persistence verified!');

// Now test full reset ALL / ALL
context.executeDirectRollReset('ALL', 'ALL');
if (context.window.allStudents[2].roll !== '' || context.window.allMasterData[2].roll !== '') {
    throw new Error('Full ALL/ALL reset did not clear ST-003!');
}
console.log('✓ Full ALL/ALL reset successfully cleared remaining students!');
console.log('\n=============================================');
console.log('MULTI-KEY RESET SUITE PASSED 100%!');
console.log('=============================================');

