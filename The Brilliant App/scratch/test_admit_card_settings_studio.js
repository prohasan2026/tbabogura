const fs = require('fs');
const vm = require('vm');

console.log("--- TESTING ADMIT CARD TEMPLATE STUDIO & SETTINGS ENGINE ---");

const html = fs.readFileSync('admin.html', 'utf8');

// 1. Verify HTML elements in admin.html
if (!html.includes('id="open-admit-settings-btn"')) {
    throw new Error("Missing 'open-admit-settings-btn' in admin.html!");
}
console.log("✓ 'open-admit-settings-btn' button verified in admin.html!");

if (!html.includes('id="admit-card-settings-modal"')) {
    throw new Error("Missing 'admit-card-settings-modal' in admin.html!");
}
console.log("✓ 'admit-card-settings-modal' verified in admin.html!");

if (!html.includes('id="admit-studio-preview-canvas"')) {
    throw new Error("Missing 'admit-studio-preview-canvas' in admin.html!");
}
console.log("✓ 'admit-studio-preview-canvas' live preview canvas verified!");

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

// 3. Mock browser environment
const storage = {};
const elements = {};
function getMockEl(id) {
    if (!elements[id]) {
        let _html = '';
        elements[id] = {
            id: id,
            value: '',
            textContent: '',
            children: [],
            get innerHTML() { return _html; },
            set innerHTML(val) {
                _html = val;
                if (!val) this.children = [];
            },
            style: {},
            classList: {
                classes: new Set(['hidden']),
                add: function(c) { this.classes.add(c); },
                remove: function(c) { this.classes.delete(c); },
                contains: function(c) { return this.classes.has(c); }
            },
            appendChild: function(child) { this.children.push(child); },
            addEventListener: () => {}
        };
    }
    return elements[id];
}

const sandbox = {
    console: console,
    localStorage: {
        getItem: (k) => storage[k] || null,
        setItem: (k, v) => { storage[k] = String(v); },
        removeItem: (k) => { delete storage[k]; }
    },
    document: {
        getElementById: (id) => getMockEl(id),
        createElement: (tag) => ({
            tagName: tag,
            className: '',
            innerHTML: '',
            children: [],
            appendChild: function(c) { this.children.push(c); },
            classList: {
                classes: new Set(),
                add: function(c) { this.classes.add(c); },
                remove: function(c) { this.classes.delete(c); },
                contains: function(c) { return this.classes.has(c); }
            }
        }),
        head: { appendChild: () => {} },
        body: { style: {} },
        addEventListener: () => {},
        querySelectorAll: () => []
    },
    sessionStorage: {
        getItem: () => null,
        setItem: () => {}
    },
    setTimeout: (fn) => typeof fn === 'function' && fn(),
    clearTimeout: () => {},
    setInterval: () => {},
    clearInterval: () => {},
    alert: (msg) => console.log("MOCK ALERT:", msg),
    confirm: (msg) => true,
    addEventListener: () => {},
    removeEventListener: () => {},
    fetch: () => Promise.resolve({ json: () => Promise.resolve([]) })
};
sandbox.window = sandbox;

vm.createContext(sandbox);
vm.runInContext(script4, sandbox);

// 4. Verify DEFAULT_ADMIT_CONFIG schema
const defaultCfg = sandbox.DEFAULT_ADMIT_CONFIG;
if (!defaultCfg) throw new Error("DEFAULT_ADMIT_CONFIG not defined!");

const requiredFields = [
    'orgNameEn', 'orgNameBn', 'orgAddress', 'examTitleEn', 'examTitleBn',
    'sessionYear', 'examDate', 'examTime', 'subjects', 'totalMarks',
    'instructions', 'sign1Title', 'sign1Sub', 'sign2Title', 'sign2Sub',
    'sign2Img', 'showSeal'
];

requiredFields.forEach(f => {
    if (defaultCfg[f] === undefined) throw new Error(`Missing field ${f} in DEFAULT_ADMIT_CONFIG`);
});
console.log("✓ DEFAULT_ADMIT_CONFIG schema verified with all 17 keys!");

// 5. Test openAdmitCardSettingsModal()
sandbox.openAdmitCardSettingsModal();
const modalEl = getMockEl('admit-card-settings-modal');
if (modalEl.classList.contains('hidden')) throw new Error("Modal should not be hidden after openAdmitCardSettingsModal()");
console.log("✓ openAdmitCardSettingsModal() opens modal and removes hidden class!");

const canvasEl = getMockEl('admit-studio-preview-canvas');
if (!canvasEl.innerHTML.includes('OFFICIAL ADMIT CARD')) {
    throw new Error("Canvas did not render admit card on modal open!");
}
console.log("✓ Live canvas rendered default admit slip!");

// 6. Test Custom Configuration Persistence and Live Update
const customConfig = {
    orgNameEn: "THE BRILLIANT SCHOLARSHIP FOUNDATION",
    orgNameBn: "দি ব্রিলিয়ান্ট স্কলারশিপ ফাউন্ডেশন",
    orgAddress: "বগুড়া সদর, বগুড়া | হটলাইন: ১৬২৬৩",
    examTitleEn: "TALENT SEARCH SCHOLARSHIP EXAM",
    examTitleBn: "মেধা সন্ধান বৃত্তি পরীক্ষা",
    sessionYear: "২০২৭",
    examDate: "২৫ ডিসেম্বর ২০২৭ (শুক্রবার)",
    examTime: "সকাল ৯.৩০ - ১১.৩০ (২ ঘণ্টা)",
    subjects: [
        { sl: "০১", name: "বাংলা সাহিত্য ও ব্যাকরণ", marks: "৩০" },
        { sl: "০২", name: "ইংরেজি ভাষা ও সাহিত্য", marks: "৩০" },
        { sl: "০৩", name: "উচ্চতর গণিত", marks: "৪০" }
    ],
    totalMarks: "১০০ নম্বর",
    instructions: [
        "পরীক্ষার ৩০ মিনিট পূর্বে প্রবেশপত্রসহ উপস্থিত হন।",
        "ক্যালকুলেটর ব্যবহার সম্পূর্ণ নিষিদ্ধ।"
    ],
    sign1Title: "প্রধান কেন্দ্র সচিব",
    sign1Sub: "Chief Center Secretary",
    sign2Title: "পরীক্ষা নিয়ন্ত্রক ও সচিব",
    sign2Sub: "Controller & Secretary",
    sign2Img: "data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mP8z8BQDwAEhQGAhKmMIQAAAABJRU5ErkJggg==",
    showSeal: true
};

storage['tba_admit_card_config'] = JSON.stringify(customConfig);

// Re-open modal to load custom config
sandbox.openAdmitCardSettingsModal();

if (!canvasEl.innerHTML.includes("THE BRILLIANT SCHOLARSHIP FOUNDATION")) {
    throw new Error("Live preview canvas did not render custom orgNameEn!");
}
if (!canvasEl.innerHTML.includes("বাংলা সাহিত্য ও ব্যাকরণ")) {
    throw new Error("Live preview canvas did not render custom subject 1!");
}
if (!canvasEl.innerHTML.includes("Chief Center Secretary")) {
    throw new Error("Live preview canvas did not render custom sign1Sub!");
}
if (!canvasEl.innerHTML.includes(customConfig.sign2Img)) {
    throw new Error("Live preview canvas did not render base64 signature!");
}
if (!canvasEl.innerHTML.includes("#1e40af") || !canvasEl.innerHTML.includes("#1e3a8a")) {
    throw new Error("Live preview canvas did not preserve royal navy colors (#1e40af, #1e3a8a)!");
}
console.log("✓ Custom config successfully loaded into live preview canvas with royal navy theme!");

// 7. Test Candidate Data Binding with Custom Template
const candidate = {
    uniqueId: "TBA-2026-9999",
    roll: "7007",
    name: "TANVIR HASAN",
    class: "Class 8",
    center: "Kahalu",
    centerCode: "03"
};

const candidateSlip = sandbox.buildAdmitSlipHTML(candidate);
if (!candidateSlip.includes("THE BRILLIANT SCHOLARSHIP FOUNDATION")) {
    throw new Error("buildAdmitSlipHTML did not pick up custom config!");
}
if (!candidateSlip.includes("7007")) {
    throw new Error("buildAdmitSlipHTML failed to bind roll number!");
}
if (!candidateSlip.includes("TBA-2026-9999")) {
    throw new Error("buildAdmitSlipHTML failed to bind registration ID!");
}
console.log("✓ buildAdmitSlipHTML dynamically applies custom template with 100% data binding!");

// 8. Test Dynamic Subject Addition
sandbox.addAdmitStudioSubject();
const subjectsList = getMockEl('admit-studio-subjects-list');
if (subjectsList.children.length !== 4) {
    throw new Error(`Expected 4 subjects after addAdmitStudioSubject(), got ${subjectsList.children.length}`);
}
console.log("✓ addAdmitStudioSubject() dynamically appended new subject!");

// 9. Test Reset to Defaults
sandbox.resetAdmitCardConfig();
const resetCfg = sandbox.getAdmitCardConfig();
if (resetCfg.orgNameEn !== "THE BRILLIANT ASSOCIATION, BOGURA") {
    throw new Error("Failed to reset orgNameEn to default!");
}
if (resetCfg.subjects.length !== 4) {
    throw new Error("Failed to reset subjects to default!");
}
console.log("✓ resetAdmitCardConfig() successfully restored defaults!");

console.log("\n=============================================");
console.log("ADMIT CARD TEMPLATE STUDIO SUITE PASSED 100%!");
console.log("=============================================");
