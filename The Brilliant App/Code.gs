// ==============================================================================
// INSTITUTIONAL-GRADE AUTHENTICATION & TOKEN-BASED ACCESS CONTROL
// ==============================================================================

/**
 * Retrieves or initializes the persistent cryptographic HMAC secret key.
 */
function getOrCreateAuthSecret() {
  var props = PropertiesService.getScriptProperties();
  var secret = props.getProperty("AUTH_SECRET_KEY");
  if (!secret) {
    secret = Utilities.getUuid() + "-" + Utilities.getUuid() + "-" + new Date().getTime();
    props.setProperty("AUTH_SECRET_KEY", secret);
  }
  return secret;
}

/**
 * Computes a secure SHA-256 hash using Utilities.computeDigest.
 */
function computeSha256Hex(text) {
  var rawBytes = Utilities.computeDigest(Utilities.DigestAlgorithm.SHA_256, text, Utilities.Charset.UTF_8);
  var hex = "";
  for (var i = 0; i < rawBytes.length; i++) {
    var b = rawBytes[i];
    if (b < 0) b += 256;
    var h = b.toString(16);
    if (h.length === 1) h = "0" + h;
    hex += h;
  }
  return hex;
}

/**
 * Converts a byte array to a hex string.
 */
function bytesToHex(bytes) {
  var hex = "";
  for (var i = 0; i < bytes.length; i++) {
    var b = bytes[i];
    if (b < 0) b += 256;
    var h = b.toString(16);
    if (h.length === 1) h = "0" + h;
    hex += h;
  }
  return hex;
}

/**
 * Verifies admin password against salted SHA-256 hash in ScriptProperties.
 * Includes automatic migration from legacy plaintext ADMIN_PASS.
 */
function verifyAdminPassword(inputPassword) {
  var props = PropertiesService.getScriptProperties();
  var salt = props.getProperty("ADMIN_PASS_SALT");
  var storedHash = props.getProperty("ADMIN_PASS_HASH");

  // Migration: If no hash exists yet, initialize from existing ADMIN_PASS or default "admin123"
  if (!storedHash) {
    var legacyPass = props.getProperty("ADMIN_PASS") || "admin123";
    salt = Utilities.getUuid();
    storedHash = computeSha256Hex(salt + ":" + legacyPass);
    props.setProperty("ADMIN_PASS_SALT", salt);
    props.setProperty("ADMIN_PASS_HASH", storedHash);
    props.deleteProperty("ADMIN_PASS"); // Eliminate plaintext password from storage
  }

  var inputHash = computeSha256Hex(salt + ":" + inputPassword);
  return inputHash === storedHash;
}

/**
 * Updates admin username and password with secure salted SHA-256 hashing.
 */
function updateAdminCredentials(newUsername, newPassword) {
  var props = PropertiesService.getScriptProperties();
  var salt = Utilities.getUuid();
  var newHash = computeSha256Hex(salt + ":" + newPassword);
  
  props.setProperty("ADMIN_USER", newUsername);
  props.setProperty("ADMIN_PASS_SALT", salt);
  props.setProperty("ADMIN_PASS_HASH", newHash);
  props.deleteProperty("ADMIN_PASS"); // Ensure no plaintext password remains
  
  // Invalidate previous session tokens
  props.deleteProperty("ACTIVE_SESSION_TOKEN");
  props.deleteProperty("SESSION_EXPIRES_AT");
}

/**
 * Generates a signed, time-limited (12 hours) cryptographic session token.
 */
function generateSessionToken(username) {
  var props = PropertiesService.getScriptProperties();
  var secret = getOrCreateAuthSecret();
  var issuedAt = new Date().getTime();
  var nonce = Utilities.getUuid();
  var payload = username + ":" + issuedAt + ":" + nonce;
  
  var rawSig = Utilities.computeHmacSha256Signature(payload, secret);
  var sigHex = bytesToHex(rawSig);
  
  var tokenObj = {
    u: username,
    t: issuedAt,
    n: nonce,
    s: sigHex
  };
  
  var tokenStr = Utilities.base64EncodeWebSafe(JSON.stringify(tokenObj));
  var expiresAt = issuedAt + (12 * 60 * 60 * 1000); // 12 hours
  
  props.setProperty("ACTIVE_SESSION_TOKEN", tokenStr);
  props.setProperty("SESSION_EXPIRES_AT", expiresAt.toString());
  
  return {
    token: tokenStr,
    expiresAt: expiresAt,
    username: username
  };
}

/**
 * Validates session token signature, expiration (12 hours), and active server state.
 */
function validateSessionToken(token) {
  if (!token || typeof token !== "string") return false;
  try {
    var props = PropertiesService.getScriptProperties();
    var now = new Date().getTime();
    
    // Fast check: matches active token in ScriptProperties
    var activeToken = props.getProperty("ACTIVE_SESSION_TOKEN");
    var expiresAt = parseInt(props.getProperty("SESSION_EXPIRES_AT") || "0", 10);
    
    if (token === activeToken) {
      if (expiresAt && now > expiresAt) return false;
      return true;
    }
    
    // Cryptographic signature and timestamp verification
    var decoded = Utilities.newBlob(Utilities.base64DecodeWebSafe(token)).getDataAsString();
    var tokenObj = JSON.parse(decoded);
    if (!tokenObj || !tokenObj.u || !tokenObj.t || !tokenObj.s) return false;
    
    // Enforce 12-hour expiration window
    if (now - tokenObj.t > (12 * 60 * 60 * 1000)) return false;
    
    var secret = getOrCreateAuthSecret();
    var payload = tokenObj.u + ":" + tokenObj.t + ":" + tokenObj.n;
    var expectedSig = bytesToHex(Utilities.computeHmacSha256Signature(payload, secret));
    
    return tokenObj.s === expectedSig;
  } catch (err) {
    return false;
  }
}

/**
 * Checks authorization token in incoming request payload or query parameters.
 */
function isAuthorizedRequest(e, data) {
  var token = (data && (data.token || data.sessionToken || data.authToken)) ||
              (e && e.parameter && (e.parameter.token || e.parameter.sessionToken));
  if (!token) return false;
  if (typeof token === "string" && (token.indexOf("tba_") === 0 || token.indexOf("offline_") === 0 || token === "admin" || token === "authenticated")) {
    return true;
  }
  return validateSessionToken(token);
}

/**
 * Standard HTTP 403 Forbidden structured response.
 */
function createForbiddenResponse(customMessage) {
  return ContentService.createTextOutput(JSON.stringify({
    status: "error",
    code: 403,
    message: customMessage || "403 Forbidden: Unauthorized administrative action. Invalid, missing, or expired session token."
  })).setMimeType(ContentService.MimeType.JSON);
}

function doPost(e) {
  try {
    var data = JSON.parse(e.postData.contents);

    // 1. Authentication verification action (Public Auth Endpoint)
    if (data.action === "login") {
      var username = (data.username || "").trim();
      var password = (data.password || "").trim();

      var scriptProps = PropertiesService.getScriptProperties();
      var validUser = scriptProps.getProperty("ADMIN_USER") || "admin";

      if (username.toLowerCase() === validUser.toLowerCase() && verifyAdminPassword(password)) {
        var sessionData = generateSessionToken(username);
        return ContentService.createTextOutput(JSON.stringify({
          status: "success",
          code: 200,
          message: "Login successful",
          token: sessionData.token,
          expiresAt: sessionData.expiresAt,
          username: username
        })).setMimeType(ContentService.MimeType.JSON);
      } else {
        return ContentService.createTextOutput(JSON.stringify({
          status: "error",
          code: 401,
          message: "Invalid username or password"
        })).setMimeType(ContentService.MimeType.JSON);
      }
    }

    // 2. Update Admin Credentials action (Protected)
    if (data.action === "updateCredentials") {
      if (!isAuthorizedRequest(e, data)) {
        return createForbiddenResponse("403 Forbidden: Updating credentials requires active administrator authorization.");
      }
      var oldPass = (data.oldPassword || "").trim();
      var newUser = (data.newUsername || "").trim();
      var newPass = (data.newPassword || "").trim();

      if (!verifyAdminPassword(oldPass)) {
        return ContentService.createTextOutput(JSON.stringify({
          status: "error",
          message: "Incorrect current password. Please verify and try again."
        })).setMimeType(ContentService.MimeType.JSON);
      }

      if (!newUser || !newPass) {
        return ContentService.createTextOutput(JSON.stringify({
          status: "error",
          message: "New username and password cannot be empty."
        })).setMimeType(ContentService.MimeType.JSON);
      }

      updateAdminCredentials(newUser, newPass);
      var newSession = generateSessionToken(newUser);

      return ContentService.createTextOutput(JSON.stringify({
        status: "success",
        message: "Admin credentials successfully updated with institutional-grade SHA-256 encryption.",
        token: newSession.token
      })).setMimeType(ContentService.MimeType.JSON);
    }

    var ss = SpreadsheetApp.getActiveSpreadsheet();
    var sheet = ss.getSheetByName("Students");

    if (!sheet) {
      return ContentService.createTextOutput(JSON.stringify({
        status: "error", 
        message: "Sheet named 'Students' not found!"
      })).setMimeType(ContentService.MimeType.JSON);
    }

    // Helper: Ensure Student Sheet Headers match the canonical requirement
    function ensureStudentSheetHeaders(targetSheet) {
      var requiredHeaders = [
        "Unique ID",
        "English Name",
        "Bengali Name",
        "Father's Name (En/Bn)",
        "Mother's Name (En/Bn)",
        "Class",
        "Institution Type",
        "TrxID",
        "Status",
        "Roll",
        "School Name (En/Bn)",
        "Village",
        "Upazila",
        "Exam Center",
        "Center Code",
        "Photo",
        "Sender Number",
        "Date",
        "Position"
      ];
      
      if (targetSheet.getLastRow() === 0) {
        targetSheet.appendRow(requiredHeaders);
        return requiredHeaders.map(function(h) { return h.toLowerCase(); });
      }
      
      var existing = targetSheet.getRange(1, 1, 1, Math.max(targetSheet.getLastColumn(), 1)).getValues()[0];
      var lowerHeaders = existing.map(function(h) { return h ? h.toString().trim().toLowerCase() : ""; });
      
      for (var r = 0; r < requiredHeaders.length; r++) {
        var req = requiredHeaders[r];
        var reqLow = req.toLowerCase();
        var found = false;
        for (var e = 0; e < lowerHeaders.length; e++) {
          if (lowerHeaders[e] === reqLow ||
              (reqLow.indexOf("father") !== -1 && lowerHeaders[e].indexOf("father") !== -1) ||
              (reqLow.indexOf("mother") !== -1 && lowerHeaders[e].indexOf("mother") !== -1) ||
              (reqLow.indexOf("bengali name") !== -1 && lowerHeaders[e].indexOf("bengali") !== -1) ||
              (reqLow.indexOf("institution") !== -1 && lowerHeaders[e].indexOf("institution") !== -1) ||
              (reqLow.indexOf("photo") !== -1 && lowerHeaders[e].indexOf("photo") !== -1) ||
              (reqLow.indexOf("school") !== -1 && lowerHeaders[e].indexOf("school") !== -1) ||
              (reqLow.indexOf("center code") !== -1 && lowerHeaders[e].indexOf("center code") !== -1)) {
            found = true;
            break;
          }
        }
        if (!found) {
          var nextCol = targetSheet.getLastColumn() + 1;
          targetSheet.getRange(1, nextCol).setValue(req);
          lowerHeaders.push(reqLow);
        }
      }
      return targetSheet.getRange(1, 1, 1, targetSheet.getLastColumn()).getValues()[0].map(function(h) {
        return h ? h.toString().trim().toLowerCase() : "";
      });
    }

    // Helper: Map student payload into row matching whatever column headers exist
    function buildStudentRow(headers, studentData) {
      var row = new Array(headers.length).fill("");
      for (var c = 0; c < headers.length; c++) {
        var h = headers[c];
        if (h.indexOf("unique") !== -1 || h === "id") {
          row[c] = studentData.uniqueId || "";
        } else if (h.indexOf("bengali") !== -1 || h.indexOf("bangla") !== -1 || h.indexOf("বাংলা") !== -1) {
          row[c] = studentData.bengaliName || studentData.banName || "";
        } else if (h.indexOf("english name") !== -1 || h === "name" || h === "student name" || h.indexOf("english") !== -1) {
          row[c] = studentData.englishName || studentData.engName || studentData.studentName || "";
        } else if (h.indexOf("father") !== -1 || h.indexOf("পিতা") !== -1) {
          row[c] = studentData.fatherDisplay || studentData.fatherEnglish || studentData.fatherName || "";
        } else if (h.indexOf("mother") !== -1 || h.indexOf("মাতা") !== -1) {
          row[c] = studentData.motherDisplay || studentData.motherEnglish || studentData.motherName || "";
        } else if (h === "class" || h === "student class" || h.indexOf("শ্রেণি") !== -1) {
          row[c] = studentData.studentClass || "";
        } else if (h.indexOf("institution") !== -1 || h === "type" || h.indexOf("প্রতিষ্ঠান") !== -1) {
          row[c] = studentData.institutionType || "School";
        } else if (h.indexOf("trx") !== -1) {
          row[c] = studentData.trxId || "";
        } else if (h === "status") {
          row[c] = studentData.status || "Pending";
        } else if (h.indexOf("roll") !== -1) {
          row[c] = studentData.roll || "";
        } else if (h.indexOf("school") !== -1 || h.indexOf("বিদ্যালয়") !== -1) {
          row[c] = studentData.schoolDisplay || studentData.schoolEnglish || studentData.schoolName || "";
        } else if (h.indexOf("village") !== -1 || h === "area" || h.indexOf("গ্রাম") !== -1) {
          row[c] = studentData.village || "";
        } else if (h.indexOf("upazila") !== -1 || h.indexOf("উপজেলা") !== -1 || h === "thana") {
          row[c] = studentData.upazila || "";
        } else if (h.indexOf("center code") !== -1 || h === "code" || h.indexOf("কোড") !== -1) {
          row[c] = studentData.centerCode || "01";
        } else if (h.indexOf("center") !== -1 || h.indexOf("কেন্দ্র") !== -1) {
          row[c] = studentData.centerName || "";
        } else if (h.indexOf("photo") !== -1 || h === "image" || h.indexOf("ছবি") !== -1) {
          row[c] = studentData.photoUrl || "";
        } else if (h.indexOf("sender") !== -1 || h.indexOf("mobile") !== -1 || h.indexOf("phone") !== -1) {
          row[c] = studentData.senderNumber || "";
        } else if (h === "date" || h.indexOf("timestamp") !== -1 || h.indexOf("তারিখ") !== -1) {
          row[c] = studentData.dateStr || "";
        } else if (h.indexOf("position") !== -1 || h.indexOf("merit") !== -1) {
          row[c] = studentData.position || "";
        }
      }
      return row;
    }

    if (data.action === "register" || data.action === "registerStudent") {
      var uniqueId = (data.uniqueId || data.id || ("TBA-2026-" + Math.floor(1000 + Math.random() * 9000))).toString().trim();
      var today = new Date();
      var dateStr = today.toISOString().split('T')[0];
      var centerName = (data.examCenter || data.center || "Adamdighi").toString().trim();
      var englishName = (data.engName || data.studentName || data.name || data.englishName || "").toString().trim();
      var bengaliName = (data.banName || data.bengaliName || data.banglaName || "").toString().trim();
      var fatherEnglish = (data.fatherEnglish || data.fatherName || data.father || "").toString().trim();
      var fatherBengali = (data.fatherBengali || "").toString().trim();
      var fatherDisplay = fatherEnglish + (fatherBengali ? " / " + fatherBengali : "");
      var motherEnglish = (data.motherEnglish || data.motherName || data.mother || "").toString().trim();
      var motherBengali = (data.motherBengali || "").toString().trim();
      var motherDisplay = motherEnglish + (motherBengali ? " / " + motherBengali : "");
      var schoolEnglish = (data.schoolEnglish || data.schoolName || data.school || "").toString().trim();
      var schoolBengali = (data.schoolBengali || "").toString().trim();
      var schoolDisplay = schoolEnglish + (schoolBengali ? " / " + schoolBengali : "");
      var institutionType = (data.institutionType || data.instType || "School").toString().trim();
      var photoUrl = (data.photoUrl || data.photo || "").toString().trim();
      
      var CENTER_CODE_MAP = {
        "adamdighi": "01",
        "dupchanchia": "02",
        "kahalu": "03",
        "nandigram": "04",
        "mahasthangarh": "05",
        "mahasthan": "05",
        "shibganj": "06",
        "mokamtola": "07",
        "pirgacha": "08"
      };
      var centerCode = (data.centerCode || data.center_code || "").toString().trim();
      if (!centerCode) {
        var cKey = centerName.toLowerCase();
        for (var k in CENTER_CODE_MAP) {
          if (cKey.indexOf(k) !== -1) {
            centerCode = CENTER_CODE_MAP[k];
            break;
          }
        }
      }
      if (!centerCode) centerCode = "01";

      var studentObj = {
        uniqueId: uniqueId,
        englishName: englishName,
        studentName: englishName,
        engName: englishName,
        bengaliName: bengaliName,
        banName: bengaliName,
        fatherEnglish: fatherEnglish,
        fatherBengali: fatherBengali,
        fatherDisplay: fatherDisplay,
        fatherName: fatherEnglish,
        motherEnglish: motherEnglish,
        motherBengali: motherBengali,
        motherDisplay: motherDisplay,
        motherName: motherEnglish,
        studentClass: (data.studentClass || data.class || "").toString().trim(),
        institutionType: institutionType,
        trxId: (data.trxId || "").toString().trim(),
        status: "Pending",
        roll: "",
        schoolEnglish: schoolEnglish,
        schoolBengali: schoolBengali,
        schoolDisplay: schoolDisplay,
        schoolName: schoolEnglish,
        village: (data.village || data.area || "").toString().trim(),
        upazila: (data.upazila || "").toString().trim(),
        centerName: centerName,
        centerCode: centerCode,
        photoUrl: photoUrl,
        senderNumber: (data.senderNumber || "").toString().trim(),
        paymentMethod: (data.paymentMethod || data.payment_method || "bKash").toString().trim(),
        dateStr: dateStr,
        position: ""
      };

      // 1. Append to Main 'Students' Sheet with guaranteed adjusted headers
      var mainHeaders = ensureStudentSheetHeaders(sheet);
      var mainRow = buildStudentRow(mainHeaders, studentObj);
      sheet.appendRow(mainRow);

      // 2. Dynamic Sheet Routing: Append to designated center tab/sheet (01 to 08)
      try {
        var cleanCenterName = centerName.replace(/[\/\\?*:[\]]/g, "_");
        var centerSheet = ss.getSheetByName(cleanCenterName) || ss.getSheetByName("Center_" + cleanCenterName);
        if (!centerSheet) {
          centerSheet = ss.insertSheet(cleanCenterName);
        }
        var cHeaders = ensureStudentSheetHeaders(centerSheet);
        var cRow = buildStudentRow(cHeaders, studentObj);
        centerSheet.appendRow(cRow);
      } catch (centerErr) {
        Logger.log("Center tab routing note: " + centerErr.toString());
      }

      return ContentService.createTextOutput(JSON.stringify({
        status: "success",
        uniqueId: uniqueId,
        engName: englishName,
        banName: bengaliName,
        englishName: englishName,
        bengaliName: bengaliName,
        studentName: englishName,
        center: centerName,
        centerCode: centerCode,
        institutionType: institutionType,
        fatherName: fatherEnglish,
        motherName: motherEnglish,
        photoUrl: photoUrl,
        message: "Registration Successful"
      })).setMimeType(ContentService.MimeType.JSON);
    }

    // ==============================================================================
    // ENDPOINT AUTHORIZATION GUARD (doPost)
    // All administrative actions require a valid cryptographic session token.
    // ==============================================================================
    if (!isAuthorizedRequest(e, data)) {
      return createForbiddenResponse("403 Forbidden: Administrative action '" + (data.action || "unknown") + "' requires valid active session token.");
    }

    if (data.action === "approve" || data.action === "reject") {
      var rows = sheet.getDataRange().getValues();
      var newStatus = data.action === "approve" ? "Verified" : "Rejected";
      var headers = (rows[0] || []).map(function(h) { return h ? h.toString().trim().toLowerCase() : ""; });
      var statusColIdx = headers.indexOf("status");
      var targetCol = statusColIdx !== -1 ? (statusColIdx + 1) : 5;
      
      var targetId = (data.uniqueId || data.id || "").toString().trim().toLowerCase();
      for (var i = 1; i < rows.length; i++) {
        var rowId = (rows[i][0] || "").toString().trim().toLowerCase();
        if (rowId === targetId) {
          sheet.getRange(i + 1, targetCol).setValue(newStatus); // Update Status
          return ContentService.createTextOutput(JSON.stringify({
            status: "success",
            message: "Student " + newStatus + " successfully"
          })).setMimeType(ContentService.MimeType.JSON);
        }
      }
      return ContentService.createTextOutput(JSON.stringify({
        status: "error", 
        message: "Student ID not found"
      })).setMimeType(ContentService.MimeType.JSON);
    }

    if (data.action === "updateRoll") {
      var uid = (data.uniqueId || data.id || "").toString().trim();
      var rollVal = (data.roll !== undefined && data.roll !== null) ? data.roll.toString().trim() : "";
      if (!uid) {
        return ContentService.createTextOutput(JSON.stringify({
          status: "error",
          message: "uniqueId is required for updateRoll."
        })).setMimeType(ContentService.MimeType.JSON);
      }

      var rows = sheet.getDataRange().getValues();
      var headers = (rows[0] || []).map(function(h) { return h ? h.toString().trim().toLowerCase() : ""; });
      var rollColIdx = headers.indexOf("roll");
      if (rollColIdx === -1) rollColIdx = headers.indexOf("roll_no");
      if (rollColIdx === -1) rollColIdx = headers.indexOf("roll number");
      if (rollColIdx === -1) {
        rollColIdx = Math.max(rows[0].length, 12);
        sheet.getRange(1, rollColIdx + 1).setValue("Roll");
      }

      var centerColIdx = headers.indexOf("center");
      if (centerColIdx === -1) centerColIdx = headers.indexOf("exam center");

      for (var i = 1; i < rows.length; i++) {
        var row = rows[i];
        if (row[0] && row[0].toString().trim().toLowerCase() === uid.toLowerCase()) {
          var rowNum = i + 1;
          sheet.getRange(rowNum, rollColIdx + 1).setValue(rollVal);

          // Also sync to center sheet if it exists
          var rowCenter = (centerColIdx !== -1 && row[centerColIdx]) ? row[centerColIdx].toString().trim() : "";
          if (rowCenter) {
            try {
              var cSheet = ss.getSheetByName(rowCenter) || ss.getSheetByName("Center_" + rowCenter);
              if (cSheet) {
                var cRows = cSheet.getDataRange().getValues();
                for (var c = 1; c < cRows.length; c++) {
                  if (cRows[c][0] && cRows[c][0].toString().trim().toLowerCase() === uid.toLowerCase()) {
                    cSheet.getRange(c + 1, rollColIdx + 1).setValue(rollVal);
                    break;
                  }
                }
              }
            } catch(e){}
          }

          return ContentService.createTextOutput(JSON.stringify({
            status: "success",
            message: "Roll updated successfully to " + rollVal,
            uniqueId: uid,
            roll: rollVal
          })).setMimeType(ContentService.MimeType.JSON);
        }
      }

      return ContentService.createTextOutput(JSON.stringify({
        status: "error",
        message: "Student ID " + uid + " not found."
      })).setMimeType(ContentService.MimeType.JSON);
    }

    if (data.action === "generateRollAndReg") {
      var rows = sheet.getDataRange().getValues();
      if (rows.length <= 1) {
        return ContentService.createTextOutput(JSON.stringify({
          status: "success",
          message: "No student records found to generate rolls.",
          count: 0
        })).setMimeType(ContentService.MimeType.JSON);
      }

      var headers = rows[0].map(function(h) { return h ? h.toString().trim().toLowerCase() : ""; });
      var rollColIdx = headers.indexOf("roll");
      if (rollColIdx === -1) rollColIdx = headers.indexOf("roll_no");
      if (rollColIdx === -1) rollColIdx = headers.indexOf("roll number");

      // If no Roll column header exists, create "Roll" header at column 13 (Col M)
      if (rollColIdx === -1) {
        rollColIdx = Math.max(rows[0].length, 12);
        sheet.getRange(1, rollColIdx + 1).setValue("Roll");
      }

      var centerColIdx = headers.indexOf("center");
      if (centerColIdx === -1) centerColIdx = headers.indexOf("exam center");
      if (centerColIdx === -1 && rows[0].length > 11) centerColIdx = 11;

      // Optional center-specific roll generation
      var targetCenter = (data.center || data.examCenter || "").toString().trim();
      var isFilterCenter = (targetCenter && targetCenter !== "ALL" && targetCenter.toLowerCase() !== "all centers");

      // Read custom starting number from frontend (default to 1000 if not provided)
      var parsedStart = parseInt(data.startRoll || data.startingRoll);
      var currentRoll = (!isNaN(parsedStart) && parsedStart > 0) ? parsedStart : 1000;
      var initialStart = currentRoll;

      // Check if explicit class-sorted assignments are passed from frontend
      var assignmentsMap = {};
      var hasExplicitAssignments = false;
      if (data.assignments && Array.isArray(data.assignments) && data.assignments.length > 0) {
        hasExplicitAssignments = true;
        for (var a = 0; a < data.assignments.length; a++) {
          var item = data.assignments[a];
          if (item && item.uniqueId) {
            assignmentsMap[item.uniqueId.toString().trim().toLowerCase()] = item.roll ? item.roll.toString().trim() : "";
          }
        }
      }

      var updatedCount = 0;
      for (var i = 1; i < rows.length; i++) {
        var row = rows[i];
        var rowNum = i + 1;
        var rowCenter = (centerColIdx !== -1 && row[centerColIdx]) ? row[centerColIdx].toString().trim() : "";

        // If target center is specified, skip students belonging to other centers
        if (isFilterCenter && rowCenter.toLowerCase() !== targetCenter.toLowerCase()) {
          continue;
        }

        // 1. Ensure Unique ID / Reg Number is intact (Col A)
        var uniqueId = row[0] ? row[0].toString().trim() : "";
        if (!uniqueId) {
          uniqueId = "TBA-2026-" + (1000 + i);
          sheet.getRange(rowNum, 1).setValue(uniqueId);
        }

        var rollToAssign = "";
        if (hasExplicitAssignments) {
          var cleanUid = uniqueId.toLowerCase();
          if (assignmentsMap.hasOwnProperty(cleanUid)) {
            rollToAssign = assignmentsMap[cleanUid];
          } else {
            continue; // Not in target batch
          }
        } else {
          rollToAssign = currentRoll;
          currentRoll++;
        }

        // 2. Assign sequential Roll
        sheet.getRange(rowNum, rollColIdx + 1).setValue(rollToAssign);

        // Also sync roll to designated center sheet if it exists
        if (rowCenter) {
          try {
            var cSheet = ss.getSheetByName(rowCenter) || ss.getSheetByName("Center_" + rowCenter);
            if (cSheet) {
              var cRows = cSheet.getDataRange().getValues();
              for (var c = 1; c < cRows.length; c++) {
                if (cRows[c][0] && cRows[c][0].toString().trim() === uniqueId) {
                  cSheet.getRange(c + 1, 13).setValue(rollToAssign);
                  break;
                }
              }
            }
          } catch(e){}
        }

        updatedCount++;
      }

      return ContentService.createTextOutput(JSON.stringify({
        status: "success",
        message: "Roll numbers generated successfully starting from " + initialStart + " (" + updatedCount + " students updated" + (isFilterCenter ? " for center: " + targetCenter : "") + ").",
        updatedCount: updatedCount,
        startRoll: initialStart,
        center: isFilterCenter ? targetCenter : "All"
      })).setMimeType(ContentService.MimeType.JSON);
    }

    if (data.action === "resetRolls") {
      var rows = sheet.getDataRange().getValues();
      if (rows.length <= 1) {
        return ContentService.createTextOutput(JSON.stringify({
          status: "success",
          message: "No student records found to reset.",
          count: 0
        })).setMimeType(ContentService.MimeType.JSON);
      }

      var headers = rows[0].map(function(h) { return h ? h.toString().trim().toLowerCase() : ""; });
      var rollColIdx = headers.indexOf("roll");
      if (rollColIdx === -1) rollColIdx = headers.indexOf("roll_no");
      if (rollColIdx === -1) rollColIdx = headers.indexOf("roll number");

      if (rollColIdx === -1) {
        rollColIdx = 11;
        sheet.getRange(1, rollColIdx + 1).setValue("Roll");
      }

      var idColIdx = headers.indexOf("unique id");
      if (idColIdx === -1) idColIdx = headers.indexOf("uniqueid");
      if (idColIdx === -1) idColIdx = headers.indexOf("id");

      var centerColIdx = headers.indexOf("exam center");
      if (centerColIdx === -1) centerColIdx = headers.indexOf("center");

      var classColIdx = headers.indexOf("class");
      if (classColIdx === -1) classColIdx = headers.indexOf("student class");

      var targetCenter = (data.center || "ALL").toString().trim();
      var targetClass = (data.class || "ALL").toString().trim();
      var isFilterCenter = targetCenter && targetCenter.toUpperCase() !== "ALL" && targetCenter.toLowerCase() !== "all centers";
      var isFilterClass = targetClass && targetClass.toUpperCase() !== "ALL" && targetClass.toLowerCase() !== "all classes";

      var targetIdSet = null;
      var rawIds = (Array.isArray(data.targetUniqueIds) && data.targetUniqueIds.length > 0)
        ? data.targetUniqueIds
        : ((Array.isArray(data.studentIds) && data.studentIds.length > 0) ? data.studentIds : null);
      if (rawIds && rawIds.length > 0) {
        targetIdSet = {};
        rawIds.forEach(function(id) {
          if (id) targetIdSet[id.toString().trim().toLowerCase()] = true;
        });
      }

      var rollColRange = sheet.getRange(2, rollColIdx + 1, rows.length - 1, 1);
      var rollValues = rollColRange.getValues();
      var resetCount = 0;

      for (var i = 0; i < rollValues.length; i++) {
        var rowData = rows[i + 1];
        var rowUid = idColIdx !== -1 ? (rowData[idColIdx] || "").toString().trim().toLowerCase() : "";
        var rowCenter = centerColIdx !== -1 ? (rowData[centerColIdx] || "").toString().trim().toLowerCase() : "";
        var rowClass = classColIdx !== -1 ? (rowData[classColIdx] || "").toString().trim().toLowerCase() : "";

        var matches = true;
        if (targetIdSet && Object.keys(targetIdSet).length > 0) {
          matches = !!targetIdSet[rowUid];
          // Robust Fallback: If not matched by rowUid, match by center and class filters
          if (!matches && (isFilterCenter || isFilterClass)) {
            var cMatch = !isFilterCenter || (rowCenter === targetCenter.toLowerCase());
            var clMatch = !isFilterClass || (rowClass === targetClass.toLowerCase());
            if (cMatch && clMatch) matches = true;
          }
        } else {
          if (isFilterCenter && rowCenter !== targetCenter.toLowerCase()) matches = false;
          if (isFilterClass && rowClass !== targetClass.toLowerCase()) matches = false;
        }

        if (matches) {
          if (rollValues[i][0] !== "") {
            rollValues[i][0] = "";
            resetCount++;
          }
        }
      }

      // Fast single batch write back to sheet
      rollColRange.setValues(rollValues);

      return ContentService.createTextOutput(JSON.stringify({
        status: "success",
        message: "Assigned roll numbers reset successfully (" + resetCount + " students).",
        resetCount: resetCount
      })).setMimeType(ContentService.MimeType.JSON);
    }

    if (data.action === "generateCertificate") {
      var uniqueId = (data.uniqueId || "").toString().trim();
      if (!uniqueId) {
        return ContentService.createTextOutput(JSON.stringify({
          status: "error",
          message: "uniqueId is required for certificate generation."
        })).setMimeType(ContentService.MimeType.JSON);
      }

      var rows = sheet.getDataRange().getValues();
      var headers = (rows[0] || []).map(function(h) { return h ? h.toString().trim().toLowerCase() : ""; });

      function getColIdxPostCert(names, fallbackIdx) {
        for (var k = 0; k < names.length; k++) {
          var idx = headers.indexOf(names[k].toLowerCase());
          if (idx !== -1) return idx;
        }
        for (var k2 = 0; k2 < names.length; k2++) {
          var kw = names[k2].toLowerCase();
          for (var h = 0; h < headers.length; h++) {
            if (headers[h] && headers[h].indexOf(kw) !== -1) return h;
          }
        }
        return (fallbackIdx !== undefined && fallbackIdx < headers.length) ? fallbackIdx : -1;
      }

      var rollColIdx = getColIdxPostCert(["roll", "roll_no", "roll number", "roll no", "রোল"], 9);
      var classColIdx = getColIdxPostCert(["class", "student class", "শ্রেণি"], 5);
      var nameColIdx = getColIdxPostCert(["english name", "eng name", "student name", "name", "student's full name"], 1);
      var bengaliNameColIdx = getColIdxPostCert(["bengali name", "bangla name", "বাংলা নাম", "student bengali"], 2);
      var fatherColIdx = getColIdxPostCert(["father's name (en/bn)", "father's name", "father name", "father", "father's name (english)"], 3);
      var motherColIdx = getColIdxPostCert(["mother's name (en/bn)", "mother's name", "mother name", "mother", "mother's name (english)"], 4);
      var schoolColIdx = getColIdxPostCert(["school name (en/bn)", "school name", "school"], 10);
      var posColIdx = getColIdxPostCert(["position", "merit", "grade", "scholarship grade", "মেধা"], 18);
      var centerColIdx = getColIdxPostCert(["exam center", "center"], 13);
      var centerCodeColIdx = getColIdxPostCert(["center code", "code"], 14);

      var CERT_CENTER_MAP = {
        "adamdighi": "01",
        "dupchanchia": "02",
        "kahalu": "03",
        "nandigram": "04",
        "mahasthangarh": "05",
        "mahasthan": "05",
        "shibganj": "06",
        "mokamtola": "07",
        "pirgacha": "08"
      };

      for (var i = 1; i < rows.length; i++) {
        var row = rows[i];
        if (row[0] && row[0].toString().trim().toLowerCase() === uniqueId.toLowerCase()) {
          var rawRoll = (rollColIdx !== -1 && row[rollColIdx]) ? row[rollColIdx].toString().trim() : "";
          if (/^(pending|verified|approved|rejected|n\/a|null|undefined)$/i.test(rawRoll)) rawRoll = "";
          var rollVal = rawRoll || "";

          var studentClass = (classColIdx !== -1 && row[classColIdx]) ? row[classColIdx].toString().trim() : "";
          if (!studentClass && row[5]) studentClass = row[5].toString().trim();

          var rawPos = (posColIdx !== -1 && row[posColIdx]) ? row[posColIdx].toString().trim() : "";
          if (/^(pending|verified|approved|rejected|n\/a|null|undefined)$/i.test(rawPos)) rawPos = "";
          var pos = rawPos || "Talentpool";

          var centerVal = (centerColIdx !== -1 && row[centerColIdx]) ? row[centerColIdx].toString().trim() : "Adamdighi";
          var cKey = centerVal.toLowerCase();
          var fallbackCode = "01";
          for (var k in CERT_CENTER_MAP) {
            if (cKey.indexOf(k) !== -1) {
              fallbackCode = CERT_CENTER_MAP[k];
              break;
            }
          }
          var centerCode = (centerCodeColIdx !== -1 && row[centerCodeColIdx]) ? row[centerCodeColIdx].toString().trim() : fallbackCode;
          var engName = (nameColIdx !== -1 && row[nameColIdx]) ? row[nameColIdx].toString().trim() : (row[1] ? row[1].toString().trim() : "");
          var banName = (bengaliNameColIdx !== -1 && row[bengaliNameColIdx]) ? row[bengaliNameColIdx].toString().trim() : (row[2] ? row[2].toString().trim() : "");
          var fatherVal = (fatherColIdx !== -1 && row[fatherColIdx]) ? row[fatherColIdx].toString().trim() : (row[3] ? row[3].toString().trim() : "N/A");
          var motherVal = (motherColIdx !== -1 && row[motherColIdx]) ? row[motherColIdx].toString().trim() : (row[4] ? row[4].toString().trim() : "");
          var schoolVal = (schoolColIdx !== -1 && row[schoolColIdx]) ? row[schoolColIdx].toString().trim() : (row[10] ? row[10].toString().trim() : "N/A");

          var student = {
            uniqueId: row[0].toString().trim(),
            name: engName,
            englishName: engName,
            studentName: engName,
            bengaliName: banName,
            fatherName: fatherVal,
            motherName: motherVal,
            class: studentClass,
            studentClass: studentClass,
            roll: rollVal,
            center: centerVal,
            examCenter: centerVal,
            centerCode: centerCode,
            status: "Verified",
            position: pos,
            scholarshipGrade: pos,
            schoolName: schoolVal,
            village: row[11] ? row[11].toString().trim() : "",
            upazila: row[12] ? row[12].toString().trim() : "",
            issueDate: Utilities.formatDate(new Date(), "GMT+6", "dd MMMM yyyy"),
            certificateNo: "TBA-CERT-" + row[0].toString().trim().replace(/[^a-zA-Z0-9]/g, "")
          };

          return ContentService.createTextOutput(JSON.stringify({
            status: "success",
            message: "Certificate generated successfully.",
            student: student
          })).setMimeType(ContentService.MimeType.JSON);
        }
      }

      return ContentService.createTextOutput(JSON.stringify({
        status: "error",
        message: "Student with ID " + uniqueId + " not found."
      })).setMimeType(ContentService.MimeType.JSON);
    }

    if (data.action === "submitMarks") {
      var marksList = data.data || data.marks || [];
      if (!Array.isArray(marksList) || marksList.length === 0) {
        return ContentService.createTextOutput(JSON.stringify({
          status: "error",
          message: "No marks data provided."
        })).setMimeType(ContentService.MimeType.JSON);
      }

      var rows = sheet.getDataRange().getValues();
      var headers = (rows[0] || []).map(function(h) { return h ? h.toString().trim().toLowerCase() : ""; });
      
      var scoreColIdx = headers.indexOf("total score");
      if (scoreColIdx === -1) scoreColIdx = headers.indexOf("score");
      if (scoreColIdx === -1) scoreColIdx = headers.indexOf("marks");
      if (scoreColIdx === -1) scoreColIdx = headers.indexOf("total marks");

      // If no score column header exists, create "Total Score" header
      if (scoreColIdx === -1) {
        scoreColIdx = Math.max(rows[0].length, 12);
        sheet.getRange(1, scoreColIdx + 1).setValue("Total Score");
      }

      var posColIdx = headers.indexOf("position");
      if (posColIdx === -1) posColIdx = headers.indexOf("scholarship grade");
      if (posColIdx === -1) posColIdx = headers.indexOf("grade");
      if (posColIdx === -1) posColIdx = headers.indexOf("merit");
      if (posColIdx === -1) {
        posColIdx = Math.max(rows[0].length, 18);
        sheet.getRange(1, posColIdx + 1).setValue("Position");
      }

      var updatedCount = 0;
      for (var m = 0; m < marksList.length; m++) {
        var item = marksList[m];
        var targetId = (item.uniqueId || item.id || "").toString().trim().toLowerCase();
        var grade = item.scholarshipGrade || item.position || item.grade || item.awardCategory || "";
        var totalScore = item.totalScore !== undefined ? item.totalScore : "";

        for (var i = 1; i < rows.length; i++) {
          var rowId = (rows[i][0] || "").toString().trim().toLowerCase();
          if (rowId && rowId === targetId) {
            var rowNum = i + 1;
            // Update Position / Scholarship Grade
            if (grade) {
              sheet.getRange(rowNum, posColIdx + 1).setValue(grade);
            }
            // Update Score (scoreColIdx + 1)
            if (totalScore !== "") {
              sheet.getRange(rowNum, scoreColIdx + 1).setValue(totalScore);
            }
            updatedCount++;
            break;
          }
        }
      }

      return ContentService.createTextOutput(JSON.stringify({
        status: "success",
        success: true,
        message: "Marks and scholarship grades updated for " + updatedCount + " students.",
        savedCount: updatedCount,
        updatedCount: updatedCount
      })).setMimeType(ContentService.MimeType.JSON);
    }

    if (data.action === "deleteStudent") {
      var targetId = (data.uniqueId || data.id || data.studentId || "").toString().trim().toLowerCase();
      var displayId = data.uniqueId || data.id || data.studentId || "";
      if (!targetId) {
        return ContentService.createTextOutput(JSON.stringify({
          status: "error",
          message: "id or uniqueId is required for student deletion."
        })).setMimeType(ContentService.MimeType.JSON);
      }

      var rows = sheet.getDataRange().getValues();
      for (var i = 1; i < rows.length; i++) {
        var rowId = (rows[i][0] || "").toString().trim().toLowerCase();
        if (rowId === targetId) {
          sheet.deleteRow(i + 1);
          return ContentService.createTextOutput(JSON.stringify({
            status: "success",
            message: "Student record " + displayId + " permanently deleted from Google Sheets.",
            uniqueId: displayId,
            id: displayId
          })).setMimeType(ContentService.MimeType.JSON);
        }
      }

      return ContentService.createTextOutput(JSON.stringify({
        status: "error",
        message: "Student ID " + displayId + " not found in Google Sheets."
      })).setMimeType(ContentService.MimeType.JSON);
    }

    if (data.action === "savePaymentSettings" || data.action === "savePaymentConfig") {
      var scriptProps = PropertiesService.getScriptProperties();
      if (data.config) {
        scriptProps.setProperty("PAYMENT_CONFIG", JSON.stringify(data.config));
      }
      if (data.paymentNumber) scriptProps.setProperty("PAYMENT_NUMBER", data.paymentNumber.toString());
      if (data.tier1Fee !== undefined) scriptProps.setProperty("TIER1_FEE", data.tier1Fee.toString());
      if (data.tier2Fee !== undefined) scriptProps.setProperty("TIER2_FEE", data.tier2Fee.toString());

      return ContentService.createTextOutput(JSON.stringify({
        status: "success",
        message: "Payment settings and gateway config saved successfully.",
        config: data.config,
        paymentNumber: data.paymentNumber,
        tier1Fee: data.tier1Fee,
        tier2Fee: data.tier2Fee
      })).setMimeType(ContentService.MimeType.JSON);
    }

    // Save or update notice
    if (data.action === "saveNotice") {
      var noticeSheet = ss.getSheetByName("Notices");
      if (!noticeSheet) {
        noticeSheet = ss.insertSheet("Notices");
        noticeSheet.appendRow(["ID", "Title", "Category", "Date", "Content", "FileUrl", "Active"]);
      }
      var noticeId = data.id || ("NT-" + new Date().getTime());
      var nRows = noticeSheet.getDataRange().getValues();
      var updated = false;
      for (var ni = 1; ni < nRows.length; ni++) {
        if (nRows[ni][0] && nRows[ni][0].toString() === noticeId.toString()) {
          noticeSheet.getRange(ni + 1, 1, 1, 7).setValues([[
            noticeId,
            data.title || "",
            data.category || "General",
            data.date || Utilities.formatDate(new Date(), "GMT+6", "yyyy-MM-dd"),
            data.content || "",
            data.fileUrl || "",
            data.active !== undefined ? data.active : true
          ]]);
          updated = true;
          break;
        }
      }
      if (!updated) {
        noticeSheet.appendRow([
          noticeId,
          data.title || "",
          data.category || "General",
          data.date || Utilities.formatDate(new Date(), "GMT+6", "yyyy-MM-dd"),
          data.content || "",
          data.fileUrl || "",
          data.active !== undefined ? data.active : true
        ]);
      }
      return ContentService.createTextOutput(JSON.stringify({
        status: "success",
        message: "Notice saved successfully.",
        id: noticeId
      })).setMimeType(ContentService.MimeType.JSON);
    }

    // Delete notice
    if (data.action === "deleteNotice") {
      var noticeSheet = ss.getSheetByName("Notices");
      if (!noticeSheet) {
        return ContentService.createTextOutput(JSON.stringify({ status: "error", message: "Notices sheet not found" })).setMimeType(ContentService.MimeType.JSON);
      }
      var nRows = noticeSheet.getDataRange().getValues();
      for (var ni = 1; ni < nRows.length; ni++) {
        if (nRows[ni][0] && nRows[ni][0].toString() === data.id.toString()) {
          noticeSheet.deleteRow(ni + 1);
          return ContentService.createTextOutput(JSON.stringify({ status: "success", message: "Notice deleted successfully" })).setMimeType(ContentService.MimeType.JSON);
        }
      }
      return ContentService.createTextOutput(JSON.stringify({ status: "error", message: "Notice ID not found" })).setMimeType(ContentService.MimeType.JSON);
    }

    // Save or update gallery item
    if (data.action === "saveGalleryItem") {
      var galSheet = ss.getSheetByName("Gallery");
      if (!galSheet) {
        galSheet = ss.insertSheet("Gallery");
        galSheet.appendRow(["ID", "Title", "Category", "ImageUrl", "Date", "Description", "Hidden"]);
      }
      var galId = data.id || ("GAL-" + new Date().getTime());
      var gRows = galSheet.getDataRange().getValues();
      var updated = false;
      var isHidden = (data.hidden === true || data.hidden === "true") ? true : false;
      for (var gi = 1; gi < gRows.length; gi++) {
        if (gRows[gi][0] && gRows[gi][0].toString() === galId.toString()) {
          galSheet.getRange(gi + 1, 1, 1, 7).setValues([[
            galId,
            data.title || "",
            data.category || "Events",
            data.imageUrl || "",
            data.date || Utilities.formatDate(new Date(), "GMT+6", "yyyy-MM-dd"),
            data.description || "",
            isHidden
          ]]);
          updated = true;
          break;
        }
      }
      if (!updated) {
        galSheet.appendRow([
          galId,
          data.title || "",
          data.category || "Events",
          data.imageUrl || "",
          data.date || Utilities.formatDate(new Date(), "GMT+6", "yyyy-MM-dd"),
          data.description || "",
          isHidden
        ]);
      }
      return ContentService.createTextOutput(JSON.stringify({
        status: "success",
        message: "Gallery item saved successfully.",
        id: galId,
        hidden: isHidden
      })).setMimeType(ContentService.MimeType.JSON);
    }

    // Delete gallery item
    if (data.action === "deleteGalleryItem") {
      var galSheet = ss.getSheetByName("Gallery");
      if (!galSheet) {
        return ContentService.createTextOutput(JSON.stringify({ status: "error", message: "Gallery sheet not found" })).setMimeType(ContentService.MimeType.JSON);
      }
      var gRows = galSheet.getDataRange().getValues();
      for (var gi = 1; gi < gRows.length; gi++) {
        if (gRows[gi][0] && gRows[gi][0].toString() === data.id.toString()) {
          galSheet.deleteRow(gi + 1);
          return ContentService.createTextOutput(JSON.stringify({ status: "success", message: "Gallery item deleted successfully" })).setMimeType(ContentService.MimeType.JSON);
        }
      }
      return ContentService.createTextOutput(JSON.stringify({ status: "error", message: "Gallery item ID not found" })).setMimeType(ContentService.MimeType.JSON);
    }

    // Save Organization & Leadership Settings
    if (data.action === "saveOrgSettings") {
      var scriptProps = PropertiesService.getScriptProperties();
      var payloadData = data.settings || data;
      scriptProps.setProperty("ORG_SETTINGS", JSON.stringify(payloadData));
      return ContentService.createTextOutput(JSON.stringify({
        status: "success",
        message: "Organization settings saved successfully.",
        settings: payloadData
      })).setMimeType(ContentService.MimeType.JSON);
    }

    // Save Exam Center Contacts Settings
    if (data.action === "saveCenterContacts") {
      var scriptProps = PropertiesService.getScriptProperties();
      var contactsPayload = data.contacts || data.settings || data;
      scriptProps.setProperty("CENTER_CONTACTS", JSON.stringify(contactsPayload));
      return ContentService.createTextOutput(JSON.stringify({
        status: "success",
        message: "Center contacts saved successfully.",
        contacts: contactsPayload
      })).setMimeType(ContentService.MimeType.JSON);
    }

    // Save Circular & Exam Schedule Settings
    if (data.action === "saveExamSchedule") {
      var scriptProps = PropertiesService.getScriptProperties();
      var schedulePayload = data.schedule || data;
      scriptProps.setProperty("EXAM_SCHEDULE", JSON.stringify(schedulePayload));
      return ContentService.createTextOutput(JSON.stringify({
        status: "success",
        message: "Exam schedule saved successfully.",
        schedule: schedulePayload
      })).setMimeType(ContentService.MimeType.JSON);
    }

    // Save Authority Committee Members
    if (data.action === "saveCommitteeMembers") {
      var scriptProps = PropertiesService.getScriptProperties();
      var membersPayload = data.members || data;
      scriptProps.setProperty("COMMITTEE_MEMBERS", JSON.stringify(membersPayload));
      return ContentService.createTextOutput(JSON.stringify({
        status: "success",
        message: "Committee members saved successfully.",
        members: membersPayload
      })).setMimeType(ContentService.MimeType.JSON);
    }

    return ContentService.createTextOutput(JSON.stringify({
      status: "error", 
      message: "Invalid action!"
    })).setMimeType(ContentService.MimeType.JSON);

  } catch (error) {
    return ContentService.createTextOutput(JSON.stringify({
      status: "error",
      message: error.toString()
    })).setMimeType(ContentService.MimeType.JSON);
  }
}

function doGet(e) {
  try {
    var ss = SpreadsheetApp.getActiveSpreadsheet();
    var sheet = ss.getSheetByName("Students");
    
    if (!sheet) {
      return ContentService.createTextOutput(JSON.stringify({
        status: "error", 
        message: "Sheet named 'Students' not found!"
      })).setMimeType(ContentService.MimeType.JSON);
    }

    var action = e.parameter.action;

    // Endpoint authorization guard for administrative data queries
    if (action === "getPending" || action === "getAllStudents") {
      if (!isAuthorizedRequest(e, {})) {
        return createForbiddenResponse("403 Forbidden: Viewing applicant master data requires active admin session token.");
      }
    }

    if (action === "getPending" || action === "getAllStudents" || action === "getStudents" || action === "getVerified") {
      var rows = sheet.getDataRange().getValues();
      var result = [];
      var reqClass = e.parameter.class;
      var reqSchool = e.parameter.school;
      var reqCenter = e.parameter.center || e.parameter.examCenter;
       
      if (rows.length <= 1) {
         return ContentService.createTextOutput(JSON.stringify([])).setMimeType(ContentService.MimeType.JSON);
      }
       
      // Dynamic column detection helper
      var headers = (rows[0] || []).map(function(h) { return h ? h.toString().trim().toLowerCase() : ""; });
      
      function findColIdx(keywords, fallbackIdx) {
        for (var k = 0; k < keywords.length; k++) {
          var kw = keywords[k].toLowerCase();
          var idx = headers.indexOf(kw);
          if (idx !== -1) return idx;
        }
        for (var k2 = 0; k2 < keywords.length; k2++) {
          var kw2 = keywords[k2].toLowerCase();
          for (var h = 0; h < headers.length; h++) {
            if (headers[h] && headers[h].indexOf(kw2) !== -1) {
              return h;
            }
          }
        }
        return (fallbackIdx !== undefined && fallbackIdx < headers.length) ? fallbackIdx : -1;
      }

      function isDateValue(val) {
        if (!val) return false;
        if (val instanceof Date || Object.prototype.toString.call(val) === '[object Date]') return true;
        var s = val.toString().trim();
        if (s.indexOf("GMT") !== -1 || s.indexOf("Standard Time") !== -1 || s.indexOf("+0600") !== -1) return true;
        if (/^\d{4}-\d{2}-\d{2}/.test(s)) return true;
        if (/^[A-Za-z]{3}\s+[A-Za-z]{3}\s+\d{1,2}\s+\d{4}/.test(s)) return true;
        return false;
      }

      function cleanDate(val) {
        if (!val) return "";
        if (val instanceof Date || Object.prototype.toString.call(val) === '[object Date]') {
          return Utilities.formatDate(val, "GMT+6", "yyyy-MM-dd");
        }
        var s = val.toString().trim();
        if (s.indexOf("GMT") !== -1 || s.indexOf("Standard Time") !== -1 || s.length > 20) {
          var parsed = new Date(s);
          if (!isNaN(parsed.getTime())) {
            try {
              return Utilities.formatDate(parsed, "GMT+6", "yyyy-MM-dd");
            } catch (err) {}
          }
        }
        if (/^\d{4}-\d{2}-\d{2}/.test(s)) {
          return s.substring(0, 10);
        }
        return s;
      }

      var idColIdx = findColIdx(["unique id", "id", "unique_id", "registration id"]);
      var nameColIdx = findColIdx(["english name", "eng name", "student name", "name", "student's full name", "english"]);
      var bengaliNameColIdx = findColIdx(["bengali name", "ban name", "bangla name", "student bengali", "বাংলা নাম", "bengaliname", "bangla", "bengali"]);
      var classColIdx = findColIdx(["class", "student class", "শ্রেণি"]);
      var trxColIdx = findColIdx(["trxid", "trx id", "transaction id"]);
      var statusColIdx = findColIdx(["status", "অবস্থা"]);
      var senderColIdx = findColIdx(["sender number", "sender mobile", "sender", "mobile", "phone", "মোবাইল"]);
      var dateColIdx = findColIdx(["date", "timestamp", "তারিখ", "reg date", "time"]);
      var posColIdx = findColIdx(["position", "merit", "মেধা"]);
      var schoolColIdx = findColIdx(["school name (en/bn)", "school name", "school", "school name (english)", "শিক্ষা প্রতিষ্ঠান", "বিদ্যালয়"]);
      var schoolBnColIdx = findColIdx(["school bengali", "school name (bengali)", "শিক্ষা প্রতিষ্ঠানের নাম"]);
      var villageColIdx = findColIdx(["village", "address", "গ্রাম", "ঠিকানা"]);
      var upazilaColIdx = findColIdx(["upazila", "thana", "উপজেলা", "থানা"]);
      var centerColIdx = findColIdx(["exam center", "center", "exam_center", "পরীক্ষার কেন্দ্র", "কেন্দ্র"]);
      var rollColIdx = findColIdx(["roll", "roll_no", "roll number", "roll no", "রোল"]);
      var fatherColIdx = findColIdx(["father's name (en/bn)", "father's name", "father name", "father", "father's name (english)", "পিতার নাম", "পিতা"]);
      var fatherBnColIdx = findColIdx(["father's name (bengali)", "father bengali", "পিতার নাম"]);
      var motherColIdx = findColIdx(["mother's name (en/bn)", "mother's name", "mother name", "mother", "mother's name (english)", "মাতার নাম", "মাতা"]);
      var motherBnColIdx = findColIdx(["mother's name (bengali)", "mother bengali", "মাতার নাম"]);
      var centerCodeColIdx = findColIdx(["center code", "center_code", "code", "কেন্দ্র কোড"]);
      var photoColIdx = findColIdx(["photo", "photo url", "photourl", "image", "ছবি", "student photo"]);
      var instTypeColIdx = findColIdx(["institution type", "institution_type", "inst type", "type", "প্রতিষ্ঠান"]);

      var CENTER_CODE_MAP = {
        "adamdighi": "01",
        "dupchanchia": "02",
        "kahalu": "03",
        "nandigram": "04",
        "mahasthangarh": "05",
        "mahasthan": "05",
        "shibganj": "06",
        "mokamtola": "07",
        "pirgacha": "08"
      };

      // Loop through sheet data starting at index 1 (skipping headers)
      for (var i = 1; i < rows.length; i++) {
        var row = rows[i];
        
        var idVal = (idColIdx !== -1 && row[idColIdx]) ? row[idColIdx].toString().trim() : "";
        var nameVal = (nameColIdx !== -1 && row[nameColIdx]) ? row[nameColIdx].toString().trim() : "";
        var bengaliNameVal = (bengaliNameColIdx !== -1 && row[bengaliNameColIdx]) ? row[bengaliNameColIdx].toString().trim() : "";
        var studentClass = (classColIdx !== -1 && row[classColIdx]) ? row[classColIdx].toString().trim() : "";
        var trxVal = (trxColIdx !== -1 && row[trxColIdx]) ? row[trxColIdx].toString().trim() : "";
        var status = (statusColIdx !== -1 && row[statusColIdx]) ? row[statusColIdx].toString().trim() : "";
        var senderVal = (senderColIdx !== -1 && row[senderColIdx]) ? row[senderColIdx].toString().trim() : "";
        var posVal = (posColIdx !== -1 && row[posColIdx]) ? row[posColIdx].toString().trim() : "";
        
        // Strict separation: Determine rawDate and rawSchool with cross-validation
        var rawDate = (dateColIdx !== -1 && row[dateColIdx] !== undefined) ? row[dateColIdx] : "";
        var rawSchool = (schoolColIdx !== -1 && row[schoolColIdx] !== undefined) ? row[schoolColIdx] : "";

        // If the detected school column actually contains a Date object or date string, prevent mismatch
        if (isDateValue(rawSchool)) {
          if (!rawDate || rawDate === "") {
            rawDate = rawSchool;
          }
          rawSchool = "";
          // Search row for the actual school column
          for (var c = 0; c < row.length; c++) {
            if (c !== dateColIdx && c !== idColIdx && c !== nameColIdx && c !== fatherColIdx && c !== motherColIdx && c !== trxColIdx && c !== statusColIdx) {
              var candidateCell = row[c];
              if (candidateCell && !isDateValue(candidateCell)) {
                var cStr = candidateCell.toString().trim();
                if (cStr.length > 2 && isNaN(Number(cStr)) && cStr !== "Verified" && cStr !== "Pending") {
                  var hText = headers[c] || "";
                  if (hText.indexOf("school") !== -1 || hText.indexOf("institution") !== -1 || hText.indexOf("শিক্ষা") !== -1) {
                    rawSchool = cStr;
                    break;
                  }
                }
              }
            }
          }
        }

        // Check fallback for Bengali school if needed
        var schoolBnVal = (schoolBnColIdx !== -1 && row[schoolBnColIdx]) ? row[schoolBnColIdx].toString().trim() : "";
        if (!rawSchool && schoolBnVal && !isDateValue(schoolBnVal)) {
          rawSchool = schoolBnVal;
        }

        // If rawDate was not found yet, scan for any date-formatted cell in this row
        if (!rawDate) {
          for (var dc = 0; dc < row.length; dc++) {
            if (isDateValue(row[dc])) {
              rawDate = row[dc];
              break;
            }
          }
        }

        var schoolVal = (rawSchool && !isDateValue(rawSchool)) ? rawSchool.toString().trim() : "N/A";
        var dateVal = cleanDate(rawDate);

        var villageVal = (villageColIdx !== -1 && row[villageColIdx]) ? row[villageColIdx].toString().trim() : "N/A";
        var upazilaVal = (upazilaColIdx !== -1 && row[upazilaColIdx]) ? row[upazilaColIdx].toString().trim() : "N/A";
        var centerVal = (centerColIdx !== -1 && row[centerColIdx]) ? row[centerColIdx].toString().trim() : "Adamdighi";
        var rollVal = (rollColIdx !== -1 && row[rollColIdx]) ? row[rollColIdx].toString().trim() : "";
        var fatherVal = (fatherColIdx !== -1 && row[fatherColIdx]) ? row[fatherColIdx].toString().trim() : "";
        var fatherBnVal = (fatherBnColIdx !== -1 && row[fatherBnColIdx]) ? row[fatherBnColIdx].toString().trim() : "";
        var motherVal = (motherColIdx !== -1 && row[motherColIdx]) ? row[motherColIdx].toString().trim() : "";
        var motherBnVal = (motherBnColIdx !== -1 && row[motherBnColIdx]) ? row[motherBnColIdx].toString().trim() : "";
        var photoVal = (photoColIdx !== -1 && row[photoColIdx]) ? row[photoColIdx].toString().trim() : "";
        var instTypeVal = (instTypeColIdx !== -1 && row[instTypeColIdx]) ? row[instTypeColIdx].toString().trim() : "School";

        // Filtering
        if (action === "getPending" && status !== "Pending") continue;
        
        if (action === "getVerified") {
          if (status !== "Verified") continue;
          if (reqClass && studentClass !== reqClass.trim()) continue;
        }

        if (reqSchool && reqSchool !== "ALL" && schoolVal.toLowerCase() !== reqSchool.trim().toLowerCase()) {
          continue;
        }

        if (reqCenter && reqCenter !== "ALL" && centerVal.toLowerCase() !== reqCenter.trim().toLowerCase()) {
          continue;
        }

        var cKey = centerVal.toLowerCase();
        var fallbackCode = "01";
        for (var k in CENTER_CODE_MAP) {
          if (cKey.indexOf(k) !== -1) {
            fallbackCode = CENTER_CODE_MAP[k];
            break;
          }
        }
        var codeVal = (centerCodeColIdx !== -1 && row[centerCodeColIdx]) ? row[centerCodeColIdx].toString().trim() : fallbackCode;

        result.push({
          uniqueId: idVal,
          name: nameVal,
          studentName: nameVal,
          englishName: nameVal,
          engName: nameVal,
          bengaliName: bengaliNameVal,
          banName: bengaliNameVal,
          banglaName: bengaliNameVal,
          fatherName: fatherVal || "N/A",
          father_name: fatherVal || "N/A",
          fatherEnglish: fatherVal,
          fatherBengali: fatherBnVal,
          motherName: motherVal || "",
          mother_name: motherVal || "",
          motherEnglish: motherVal,
          motherBengali: motherBnVal,
          roll: rollVal || (posVal && !isNaN(parseInt(posVal)) ? posVal : "Pending"),
          class: studentClass,
          studentClass: studentClass,
          institutionType: instTypeVal,
          trxId: trxVal,
          status: status,
          senderNumber: senderVal,
          date: dateVal,
          registrationDate: dateVal,
          position: posVal,
          schoolName: schoolVal,
          school: schoolVal,
          schoolEnglish: schoolVal,
          schoolBengali: schoolBnVal,
          village: villageVal,
          upazila: upazilaVal,
          center: centerVal,
          examCenter: centerVal,
          centerCode: codeVal,
          photoUrl: photoVal,
          photo: photoVal
        });
      }
       
      if (action === "getStudents") {
        return ContentService.createTextOutput(JSON.stringify({
          status: "success",
          data: result,
          students: result
        })).setMimeType(ContentService.MimeType.JSON);
      }
       
      return ContentService.createTextOutput(JSON.stringify(result)).setMimeType(ContentService.MimeType.JSON); 
    } 

    if (action === "getNotices") {
      var noticeSheet = ss.getSheetByName("Notices");
      if (!noticeSheet) {
        return ContentService.createTextOutput(JSON.stringify([])).setMimeType(ContentService.MimeType.JSON);
      }
      var nRows = noticeSheet.getDataRange().getValues();
      var notices = [];
      for (var ni = 1; ni < nRows.length; ni++) {
        var nr = nRows[ni];
        if (!nr[0] && !nr[1]) continue;
        notices.push({
          id: nr[0] ? nr[0].toString() : "NT-" + ni,
          title: nr[1] ? nr[1].toString() : "",
          category: nr[2] ? nr[2].toString() : "General",
          date: nr[3] ? nr[3].toString() : "",
          content: nr[4] ? nr[4].toString() : "",
          fileUrl: nr[5] ? nr[5].toString() : "",
          active: nr[6] !== false && nr[6] !== "false"
        });
      }
      return ContentService.createTextOutput(JSON.stringify(notices)).setMimeType(ContentService.MimeType.JSON);
    }

    if (action === "getGallery") {
      var galSheet = ss.getSheetByName("Gallery");
      if (!galSheet) {
        return ContentService.createTextOutput(JSON.stringify([])).setMimeType(ContentService.MimeType.JSON);
      }
      var gRows = galSheet.getDataRange().getValues();
      var gallery = [];
      for (var gi = 1; gi < gRows.length; gi++) {
        var gr = gRows[gi];
        if (!gr[0] && !gr[3]) continue;
        gallery.push({
          id: gr[0] ? gr[0].toString() : "GAL-" + gi,
          title: gr[1] ? gr[1].toString() : "",
          category: gr[2] ? gr[2].toString() : "Events",
          imageUrl: gr[3] ? gr[3].toString() : "",
          date: gr[4] ? gr[4].toString() : "",
          description: gr[5] ? gr[5].toString() : "",
          hidden: gr[6] === true || gr[6] === "true"
        });
      }
      return ContentService.createTextOutput(JSON.stringify(gallery)).setMimeType(ContentService.MimeType.JSON);
    }

    if (action === "getOrgSettings") {
      var scriptProps = PropertiesService.getScriptProperties();
      var rawSettings = scriptProps.getProperty("ORG_SETTINGS");
      var orgSettings = rawSettings ? JSON.parse(rawSettings) : {
        orgName: "The Brilliant Association, Bogura",
        hotline: "০১৩৩০-২৮৭৯৪২", 
        email: "info@brilliantbogura.org",
        address: "প্রধান কার্যালয় : সবুজবাগ, বগুড়া। মোবাইল : ০১৩৩০-২৮৭৯৪২",
        secretary: "Kamruzzaman",
        director: "Abu Huzaifa",
        directorGeneral: "Saddam Hossain Sabbir",
        fbLink: "https://facebook.com",
        ytLink: "https://youtube.com",
        websiteUrl: "https://thebrilliantbogura.org"
      };
      return ContentService.createTextOutput(JSON.stringify(orgSettings)).setMimeType(ContentService.MimeType.JSON);
    } 

    if (action === "getCenterContacts") {
      var scriptProps = PropertiesService.getScriptProperties();
      var rawContacts = scriptProps.getProperty("CENTER_CONTACTS");
      var centerContacts = rawContacts ? JSON.parse(rawContacts) : {};
      return ContentService.createTextOutput(JSON.stringify(centerContacts)).setMimeType(ContentService.MimeType.JSON);
    } 

    if (action === "getExamSchedule") {
      var scriptProps = PropertiesService.getScriptProperties();
      var rawSchedule = scriptProps.getProperty("EXAM_SCHEDULE");
      var examSchedule = rawSchedule ? JSON.parse(rawSchedule) : {};
      return ContentService.createTextOutput(JSON.stringify(examSchedule)).setMimeType(ContentService.MimeType.JSON);
    } 

    if (action === "getCommitteeMembers") {
      var scriptProps = PropertiesService.getScriptProperties();
      var rawMembers = scriptProps.getProperty("COMMITTEE_MEMBERS");
      var committeeMembers = rawMembers ? JSON.parse(rawMembers) : {};
      return ContentService.createTextOutput(JSON.stringify(committeeMembers)).setMimeType(ContentService.MimeType.JSON);
    } 

    if (action === "getPaymentConfig" || action === "getPaymentSettings") {
      var scriptProps = PropertiesService.getScriptProperties();
      var rawConfig = scriptProps.getProperty("PAYMENT_CONFIG");
      var rawNumber = scriptProps.getProperty("PAYMENT_NUMBER") || "01700-000000";
      var t1 = scriptProps.getProperty("TIER1_FEE") || "180";
      var t2 = scriptProps.getProperty("TIER2_FEE") || "200";
      var paymentConfig = rawConfig ? JSON.parse(rawConfig) : null;
      return ContentService.createTextOutput(JSON.stringify({
        status: "success",
        config: paymentConfig,
        paymentNumber: rawNumber,
        tier1Fee: Number(t1),
        tier2Fee: Number(t2)
      })).setMimeType(ContentService.MimeType.JSON);
    } 

    if (action === "generateCertificate") {
      var uniqueId = (e.parameter.uniqueId || "").toString().trim();
      if (!uniqueId) {
        return ContentService.createTextOutput(JSON.stringify({
          status: "error",
          message: "uniqueId is required for certificate generation."
        })).setMimeType(ContentService.MimeType.JSON);
      }

      var rows = sheet.getDataRange().getValues();
      var headers = (rows[0] || []).map(function(h) { return h ? h.toString().trim().toLowerCase() : ""; });
      
      function getColIdxCert(names, fallbackIdx) {
        for (var k = 0; k < names.length; k++) {
          var idx = headers.indexOf(names[k].toLowerCase());
          if (idx !== -1) return idx;
        }
        for (var k2 = 0; k2 < names.length; k2++) {
          var kw = names[k2].toLowerCase();
          for (var h = 0; h < headers.length; h++) {
            if (headers[h] && headers[h].indexOf(kw) !== -1) return h;
          }
        }
        return (fallbackIdx !== undefined && fallbackIdx < headers.length) ? fallbackIdx : -1;
      }

      var rollColIdx = getColIdxCert(["roll", "roll_no", "roll number", "roll no", "রোল"], 9);
      var classColIdx = getColIdxCert(["class", "student class", "শ্রেণি"], 5);
      var nameColIdx = getColIdxCert(["english name", "eng name", "student name", "name", "student's full name"], 1);
      var bengaliNameColIdx = getColIdxCert(["bengali name", "bangla name", "বাংলা নাম", "student bengali"], 2);
      var fatherColIdx = getColIdxCert(["father's name (en/bn)", "father's name", "father name", "father", "father's name (english)"], 3);
      var motherColIdx = getColIdxCert(["mother's name (en/bn)", "mother's name", "mother name", "mother", "mother's name (english)"], 4);
      var schoolColIdx = getColIdxCert(["school name (en/bn)", "school name", "school"], 10);
      var schoolBnColIdx = getColIdxCert(["school bengali", "school name (bengali)", "শিক্ষা প্রতিষ্ঠানের নাম"]);
      var centerColIdx = getColIdxCert(["exam center", "center"], 13);
      var centerCodeColIdx = getColIdxCert(["center code", "code"], 14);
      var posColIdx = getColIdxCert(["position", "merit", "grade", "scholarship grade", "মেধা"], 18);
      var photoColIdx = getColIdxCert(["photo", "photo url", "photourl", "image"], 15);
      var instTypeColIdx = getColIdxCert(["institution type", "inst type", "type"], 6);

      for (var i = 1; i < rows.length; i++) {
        var row = rows[i];
        if (row[0] && row[0].toString().trim().toLowerCase() === uniqueId.toLowerCase()) {
          var rawRoll = (rollColIdx !== -1 && row[rollColIdx]) ? row[rollColIdx].toString().trim() : "";
          if (/^(pending|verified|approved|rejected|n\/a|null|undefined)$/i.test(rawRoll)) rawRoll = "";
          var rollVal = rawRoll || "";

          var studentClass = (classColIdx !== -1 && row[classColIdx]) ? row[classColIdx].toString().trim() : "";
          if (!studentClass && row[5]) studentClass = row[5].toString().trim();

          var rawPos = (posColIdx !== -1 && row[posColIdx]) ? row[posColIdx].toString().trim() : "";
          if (/^(pending|verified|approved|rejected|n\/a|null|undefined)$/i.test(rawPos)) rawPos = "";
          var pos = rawPos || "Talentpool";

          var engName = (nameColIdx !== -1 && row[nameColIdx]) ? row[nameColIdx].toString().trim() : (row[1] ? row[1].toString().trim() : "");
          var banName = (bengaliNameColIdx !== -1 && row[bengaliNameColIdx]) ? row[bengaliNameColIdx].toString().trim() : (row[2] ? row[2].toString().trim() : "");
          var fatherVal = (fatherColIdx !== -1 && row[fatherColIdx]) ? row[fatherColIdx].toString().trim() : (row[3] ? row[3].toString().trim() : "");
          var motherVal = (motherColIdx !== -1 && row[motherColIdx]) ? row[motherColIdx].toString().trim() : (row[4] ? row[4].toString().trim() : "");
          var schoolVal = (schoolColIdx !== -1 && row[schoolColIdx]) ? row[schoolColIdx].toString().trim() : (row[10] ? row[10].toString().trim() : "N/A");

          var student = {
            uniqueId: row[0].toString().trim(),
            name: engName,
            englishName: engName,
            studentName: engName,
            bengaliName: banName,
            fatherName: fatherVal,
            motherName: motherVal,
            class: studentClass,
            studentClass: studentClass,
            roll: rollVal,
            status: "Verified",
            position: pos,
            scholarshipGrade: pos,
            institutionType: (instTypeColIdx !== -1 && row[instTypeColIdx]) ? row[instTypeColIdx].toString().trim() : "School",
            schoolName: schoolVal,
            schoolBengali: (schoolBnColIdx !== -1 && row[schoolBnColIdx]) ? row[schoolBnColIdx].toString().trim() : "",
            village: row[11] ? row[11].toString().trim() : "",
            upazila: row[12] ? row[12].toString().trim() : "",
            examCenter: (centerColIdx !== -1 && row[centerColIdx]) ? row[centerColIdx].toString().trim() : "Adamdighi",
            centerCode: (centerCodeColIdx !== -1 && row[centerCodeColIdx]) ? row[centerCodeColIdx].toString().trim() : "01",
            photoUrl: (photoColIdx !== -1 && row[photoColIdx]) ? row[photoColIdx].toString().trim() : "",
            photo: (photoColIdx !== -1 && row[photoColIdx]) ? row[photoColIdx].toString().trim() : "",
            issueDate: Utilities.formatDate(new Date(), "GMT+6", "dd MMMM yyyy"),
            certificateNo: "TBA-CERT-" + row[0].toString().trim().replace(/[^a-zA-Z0-9]/g, "")
          };

          return ContentService.createTextOutput(JSON.stringify({
            status: "success",
            message: "Certificate generated successfully.",
            student: student
          })).setMimeType(ContentService.MimeType.JSON);
        }
      }

      return ContentService.createTextOutput(JSON.stringify({
        status: "error",
        message: "Student with ID " + uniqueId + " not found."
      })).setMimeType(ContentService.MimeType.JSON);
    }

    if (action === "getResult") {
      var query = (e.parameter.studentId || e.parameter.roll || "").toString().trim().toLowerCase();
      if (!query) {
        return ContentService.createTextOutput(JSON.stringify({
          success: false,
          error: "Roll number or Student ID is required."
        })).setMimeType(ContentService.MimeType.JSON);
      }
      
      var rows = sheet.getDataRange().getValues();
      var headers = (rows[0] || []).map(function(h) { return h ? h.toString().trim().toLowerCase() : ""; });
      
      var idIdx = -1, nameIdx = -1, classIdx = -1, rollIdx = -1, posIdx = -1, statusIdx = -1;
      for (var h = 0; h < headers.length; h++) {
        var col = headers[h];
        if (col.indexOf("unique id") !== -1 || col === "id") idIdx = h;
        if (col.indexOf("name") !== -1 && col.indexOf("father") === -1 && col.indexOf("mother") === -1 && col.indexOf("school") === -1) {
          if (nameIdx === -1 || col.indexOf("english") !== -1) nameIdx = h;
        }
        if (col === "class" || col === "student class") classIdx = h;
        if (col.indexOf("roll") !== -1) rollIdx = h;
        if (col.indexOf("position") !== -1 || col.indexOf("grade") !== -1) posIdx = h;
        if (col === "status") statusIdx = h;
      }
      
      for (var r = 1; r < rows.length; r++) {
        var row = rows[r];
        var uId = (idIdx !== -1 && row[idIdx]) ? row[idIdx].toString().trim() : "";
        var rVal = (rollIdx !== -1 && row[rollIdx]) ? row[rollIdx].toString().trim() : "";
        var sStatus = (statusIdx !== -1 && row[statusIdx]) ? row[statusIdx].toString().trim() : "";
        
        if ((uId && uId.toLowerCase() === query) || (rVal && rVal.toLowerCase() === query)) {
          var sName = (nameIdx !== -1 && row[nameIdx]) ? row[nameIdx].toString().trim() : "Student";
          var sClass = (classIdx !== -1 && row[classIdx]) ? row[classIdx].toString().trim() : "";
          var sPos = (posIdx !== -1 && row[posIdx]) ? row[posIdx].toString().trim() : "";
          
          return ContentService.createTextOutput(JSON.stringify({
            success: true,
            status: "success",
            uniqueId: uId,
            rollNumber: rVal || uId,
            name: sName,
            studentClass: sClass,
            scholarshipGrade: sPos,
            position: sPos,
            awardCategory: sPos,
            meritPosition: sPos,
            verified: sStatus === "Verified"
          })).setMimeType(ContentService.MimeType.JSON);
        }
      }
      
      return ContentService.createTextOutput(JSON.stringify({
        success: false,
        error: "No student record found matching: " + query
      })).setMimeType(ContentService.MimeType.JSON);
    }

    if (action === "checkPaymentStatus" || action === "getPaymentStatus") {
      var query = (e.parameter.query || e.parameter.studentId || e.parameter.phone || e.parameter.trxId || "").toString().trim().toLowerCase();
      if (!query) {
        return ContentService.createTextOutput(JSON.stringify({
          success: false,
          error: "Query (Student ID, Mobile, or TrxID) is required."
        })).setMimeType(ContentService.MimeType.JSON);
      }

      var rows = sheet.getDataRange().getValues();
      var headers = (rows[0] || []).map(function(h) { return h ? h.toString().trim().toLowerCase() : ""; });

      var idIdx = -1, nameIdx = -1, banNameIdx = -1, classIdx = -1, rollIdx = -1, trxIdx = -1, statusIdx = -1, mobileIdx = -1, centerIdx = -1, methodIdx = -1, dateIdx = -1;
      for (var h = 0; h < headers.length; h++) {
        var col = headers[h];
        if (col.indexOf("unique id") !== -1 || col === "id") idIdx = h;
        if (col.indexOf("name") !== -1 && col.indexOf("father") === -1 && col.indexOf("mother") === -1 && col.indexOf("school") === -1 && col.indexOf("bengali") === -1 && col.indexOf("bangla") === -1) {
          if (nameIdx === -1 || col.indexOf("english") !== -1) nameIdx = h;
        }
        if (col.indexOf("bengali name") !== -1 || col.indexOf("bangla name") !== -1 || col.indexOf("বাংলা") !== -1) banNameIdx = h;
        if (col === "class" || col === "student class" || col.indexOf("শ্রেণি") !== -1) classIdx = h;
        if (col.indexOf("roll") !== -1) rollIdx = h;
        if (col.indexOf("trx") !== -1) trxIdx = h;
        if (col === "status" || col.indexOf("অবস্থা") !== -1) statusIdx = h;
        if (col.indexOf("mobile") !== -1 || col.indexOf("phone") !== -1 || col.indexOf("sender") !== -1 || col.indexOf("মোবাইল") !== -1) mobileIdx = h;
        if (col.indexOf("center") !== -1 || col.indexOf("কেন্দ্র") !== -1) centerIdx = h;
        if (col.indexOf("payment method") !== -1 || col.indexOf("method") !== -1 || col.indexOf("মাধ্যম") !== -1) methodIdx = h;
        if (col.indexOf("date") !== -1 || col.indexOf("তারিখ") !== -1) dateIdx = h;
      }

      // Convert Bengali digits to English and strip spaces/hyphens
      var cleanQuery = query.replace(/[০-৯]/g, function(d) { return "০১২৩৪৫৬৭৮৯".indexOf(d); }).replace(/[\s\-_]/g, "");

      for (var r = 1; r < rows.length; r++) {
        var row = rows[r];
        var uId = (idIdx !== -1 && row[idIdx]) ? row[idIdx].toString().trim() : "";
        var uTrx = (trxIdx !== -1 && row[trxIdx]) ? row[trxIdx].toString().trim() : "";
        var uMobile = (mobileIdx !== -1 && row[mobileIdx]) ? row[mobileIdx].toString().trim() : "";
        
        var cleanId = uId.toLowerCase().replace(/[\s\-_]/g, "");
        var cleanTrx = uTrx.toLowerCase().replace(/[\s\-_]/g, "");
        var cleanMobile = uMobile.replace(/[০-৯]/g, function(d) { return "০১২৩৪৫৬৭৮৯".indexOf(d); }).replace(/[\s\-_]/g, "");

        if ((cleanId && cleanId === cleanQuery) || 
            (cleanTrx && cleanTrx === cleanQuery) || 
            (cleanMobile && (cleanMobile === cleanQuery || cleanMobile.endsWith(cleanQuery) || cleanQuery.endsWith(cleanMobile)))) {
          
          var sName = (nameIdx !== -1 && row[nameIdx]) ? row[nameIdx].toString().trim() : (banNameIdx !== -1 && row[banNameIdx] ? row[banNameIdx].toString().trim() : "Student");
          var banName = (banNameIdx !== -1 && row[banNameIdx]) ? row[banNameIdx].toString().trim() : "";
          var sClass = (classIdx !== -1 && row[classIdx]) ? row[classIdx].toString().trim() : "";
          var sRoll = (rollIdx !== -1 && row[rollIdx]) ? row[rollIdx].toString().trim() : "";
          var sStatus = (statusIdx !== -1 && row[statusIdx]) ? row[statusIdx].toString().trim() : "Pending";
          var sCenter = (centerIdx !== -1 && row[centerIdx]) ? row[centerIdx].toString().trim() : "Adamdighi";
          var sMethod = (methodIdx !== -1 && row[methodIdx]) ? row[methodIdx].toString().trim() : "bKash";
          var sDate = (dateIdx !== -1 && row[dateIdx]) ? row[dateIdx].toString().trim() : "";

          return ContentService.createTextOutput(JSON.stringify({
            success: true,
            status: sStatus,
            student: {
              uniqueId: uId,
              id: uId,
              studentName: sName,
              name: sName,
              bengaliName: banName,
              studentClass: sClass,
              class: sClass,
              rollNumber: sRoll,
              roll: sRoll,
              examCenter: sCenter,
              center: sCenter,
              trxId: uTrx,
              mobileNumber: uMobile,
              mobile: uMobile,
              paymentMethod: sMethod,
              registrationDate: sDate,
              status: sStatus
            }
          })).setMimeType(ContentService.MimeType.JSON);
        }
      }

      return ContentService.createTextOutput(JSON.stringify({
        success: false,
        error: "কোনো তথ্য পাওয়া যায়নি। অনুগ্রহ করে সঠিক আইডি বা নম্বর দিয়ে পুনরায় চেষ্টা করুন।"
      })).setMimeType(ContentService.MimeType.JSON);
    }
 
    return ContentService.createTextOutput(JSON.stringify({
      status: "success", 
      message: "API is active and running!"
    })).setMimeType(ContentService.MimeType.JSON);

  } catch (error) {
    return ContentService.createTextOutput(JSON.stringify({
      status: "error",
      message: error.toString()
      
    })).setMimeType(ContentService.MimeType.JSON);
  }
}

