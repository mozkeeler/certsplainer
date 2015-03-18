var pem = "-----BEGIN CERTIFICATE-----" +
          "MIIBEDCBuwICAP8wDQYJKoZIhvcNAQEFBQAwFDESMBAGA1UEAxMJbG9jYWxob3N0" +
          "MB4XDTE1MDIwNjAxMDg1MFoXDTIzMDYwNjAxMDg1MFowFDESMBAGA1UEAxMJbG9j" +
          "YWxob3N0MFowDQYJKoZIhvcNAQEBBQADSQAwRgJBANOcXjAyMipXbYP3DhkFt9uH" +
          "hc1k5WottUEwGH6xmUnqtZZSPrMLUl/9+IchxzXhRS9kxj4OySaXZzbCucdAO4UC" +
          "AQMwDQYJKoZIhvcNAQEFBQADQQCcL/7p4Wvmx/E7bvf8CPBxehsU+gxIE/LkQzZu" +
          "ceSEH4lYXdcT5cVxZxSgeANNrsiLOtGNkg78erW/2L6+JGng" +
          "-----END CERTIFICATE-----";

function setField(field, value) {
  document.getElementById(field).textContent = value;
}

function setViolation(field) {
  document.getElementById(field).setAttribute("violation", true);
}

function unsetViolation(field) {
  document.getElementById(field).removeAttribute("violation");
}

function formatRDN(rdn) {
  var result = "";
  rdn.attributes.forEach(function(attribute) {
    if (attribute.shortName) {
      var spacer = result.length ? ", " : "";
      result += spacer + attribute.shortName + "=" + attribute.value;
    }
  });
  return result;
}

function formatAltName(altName) {
  switch (altName.type) {
    case 2: return "DNS name:" + altName.value;
    case 7: return "IP address:" + altName.ip;
    default: return "(unsupported)";
  }
}

function formatSubjectAltNames(altNames) {
  if (!altNames) {
    return "(no subject alternative names extension)";
  }
  if (!altNames.altNames || altNames.altNames.length < 1) {
    return "(empty subject alternative names extension)";
  }
  var result = "";
  altNames.altNames.forEach(function(altName) {
    var spacer = result.length ? ", " : "";
    result += spacer + formatAltName(altName);
  });
  return result;
}

function clearFields() {
  for (var id of ["version", "serialNumber", "signature", "issuer", "notBefore",
                  "notAfter", "subject", "subjectAltName",
                  "signatureAlgorithm", "keySize", "exponent"]) {
    setField(id, "");
    unsetViolation(id);
  }
}

function clearExtensions() {
  var extensionsTable = document.getElementById("extensions");
  while (extensionsTable.children.length > 0) {
    extensionsTable.children[0].remove();
  }
}

function byteStringToHex(byteString) {
  var result = "";
  for (var i = 0; i < byteString.length; i++) {
    var hex = byteString.charCodeAt(i).toString(16);
    if (hex.length < 2) {
      hex = "0" + hex;
    }
    result += (result.length > 0 ? " " : "") + hex;
  }
  return result;
}

function formatBasicConstraints(extension) {
  var result = "cA: " + extension.cA;
  if ("pathLenConstraint" in extension) {
    result += ", pathLenConstraint: " + extension.pathLenConstraint;
  }
  return result;
}

function formatKeyUsage(extension) {
  var result = "";
  for (var usage of ["digitalSignature", "nonRepudiation", "keyEncipherment",
                     "dataEncipherment", "keyAgreement", "keyCertSign"]) {
    if (extension[usage]) {
      result += (result.length > 0 ? ", " : "") + usage;
    }
  }
  return result;
}

function formatExtKeyUsage(extension) {
  var result = "";
  for (var usage of ["serverAuth"]) {
    if (extension[usage]) {
      result += (result.length > 0 ? ", " : "") + usage;
    }
  }
  return result;
}

function formatSubjectKeyIdentifier(extension) {
  return extension.subjectKeyIdentifier;
}

function formatSubjectAltName(extension) {
  return formatSubjectAltNames(extension);
}

function byteStringToBytes(byteString) {
  var bytes = [];
  for (var i = 0; i < byteString.length; i++) {
    bytes.push(byteString.charCodeAt(i));
  }
  return bytes;
}

function formatAuthorityInfoAccess(extension) {
  var accessDescriptions = ASN1.decode(byteStringToBytes(extension.value));
  var output = "";
  for (var i = 0; i < accessDescriptions.sub.length; i++) {
    var accessDescription = accessDescriptions.sub[i];
    var accessMethod = accessDescription.sub[0];
    var accessLocation = accessDescription.sub[1];
    output += (output ? ", " : "") + oids[accessMethod.content()].d + ": " +
              accessLocation.content();
  }
  return output;
}

function formatCertificatePolicies(extension) {
  var certificatePolicies = ASN1.decode(byteStringToBytes(extension.value));
  var output = "";
  for (var i = 0; i < certificatePolicies.sub.length; i++) {
    var policyInformation = certificatePolicies.sub[i];
    var policyIdentifier = policyInformation.sub[0];
    output += (output ? ", " : "") +
              oidToDescription(policyIdentifier.content());
  }
  return output;
}

// This really only handles DNS names
function formatNameConstraints(extension) {
  var nameConstraints = ASN1.decode(byteStringToBytes(extension.value));
  var permittedSubtrees = nameConstraints.sub[0];
  var permittedOutput = "";
  for (var i = 0; i < permittedSubtrees.sub.length; i++) {
    var permittedSubtree = permittedSubtrees.sub[i];
    permittedOutput += (permittedOutput ? ", " : "") +
                       permittedSubtrees.sub[i].sub[0].content();
  }
  var excludedSubtrees = nameConstraints.sub[1];
  var excludedOutput = "";
  for (var i = 0; i < excludedSubtrees.sub.length; i++) {
    excludedOutput += (excludedOutput ? ", " : "") +
                       excludedSubtrees.sub[i].sub[0].content();
  }
  return "permitted: " + permittedOutput + "; excluded: " + excludedOutput;
}

function extensionToString(extension) {
  try {
    switch (getExtensionName(extension)) {
      case "basicConstraints": return formatBasicConstraints(extension);
      case "keyUsage": return formatKeyUsage(extension);
      case "extKeyUsage": return formatExtKeyUsage(extension);
      case "subjectKeyIdentifier": return formatSubjectKeyIdentifier(extension);
      case "subjectAltName": return formatSubjectAltName(extension);
      case "authorityInfoAccess": return formatAuthorityInfoAccess(extension);
      case "nameConstraints": return formatNameConstraints(extension);
      case "certificatePolicies": return formatCertificatePolicies(extension);
      case "authorityKeyIdentifier":
      case "certificatePolicies":
      case "cRLDistributionPoints":
      case "issuerAltName":
      default: break;
    }
  } catch (e) {
    console.log(e);
  }
  return byteStringToHex(extension.value);
}

function oidToDescription(oidString) {
  if (oidString in oids) {
    return oids[oidString].d;
  }
  return oidString;
}

// forge.js has some OID -> name mappings, but asn1.js has more. Try the
// former, then try the latter, then just give up and use the string
// representation of the OID.
function getExtensionName(extension) {
  if ("name" in extension && extension.name.length > 0) {
    return extension.name;
  }
  return oidToDescription(extension.id);
}

function decode(pem, asEndEntity) {
  clearFields();
  clearExtensions();

  var cert = null;
  try {
    cert = forge.pki.certificateFromPem(pem);
  } catch (e) {}
  // Try with the BEGIN/END wrappers if the above failed
  if (!cert) {
    cert = forge.pki.certificateFromPem("-----BEGIN CERTIFICATE-----" + pem +
                                        "-----END CERTIFICATE-----");
  }
  setField("version", cert.version + 1);
  setField("serialNumber", cert.serialNumber);
  setField("signature", forge.pki.oids[cert.siginfo.algorithmOid]);
  setField("issuer", formatRDN(cert.issuer));
  setField("notBefore", cert.validity.notBefore);
  setField("notAfter", cert.validity.notAfter);
  setField("subject", formatRDN(cert.subject));
  if (asEndEntity) {
    setField("subjectAltName",
      formatSubjectAltNames(cert.getExtension({name: 'subjectAltName'})));
    document.getElementById("subjectAltNameLabel").setAttribute("class", "");
  } else {
    document.getElementById("subjectAltNameLabel").setAttribute("class",
                                                                "hidden");
  }
  setField("signatureAlgorithm", forge.pki.oids[cert.signatureOid]);
  setField("keySize", cert.publicKey.n.bitLength());
  setField("exponent", cert.publicKey.e.toString());

  if (asEndEntity) {
    if ((cert.version + 1) != 3) {
      setViolation("version");
    }
    if ((cert.validity.notAfter - cert.validity.notBefore) /
        (1000 * 3600 * 24 * 366) > 5) {
      setViolation("notBefore");
      setViolation("notAfter");
    }
    if (!cert.getExtension({name: 'subjectAltName'})) {
      setViolation("subjectAltName");
    }
    if (forge.pki.oids[cert.signatureOid] != "sha256WithRSAEncryption" &&
        forge.pki.oids[cert.signatureOid] != "sha512WithRSAEncryption") {
      setViolation("signatureAlgorithm");
    }
    if (cert.publicKey.n.bitLength() <= 1024) {
      setViolation("keySize");
    }
    if (cert.publicKey.e.toString() == "3") {
      setViolation("exponent");
    }
  }
  document.getElementById("pem").value = forge.pki.certificateToPem(cert);

  var extensionsTable = document.getElementById("extensions");
  for (var extension of cert.extensions) {
    var tr = document.createElement("tr");
    var tdName = document.createElement("td");
    tdName.textContent = getExtensionName(extension);
    tr.appendChild(tdName);
    var tdValue = document.createElement("td");
    tdValue.textContent = extensionToString(extension);
    tr.appendChild(tdValue);
    extensionsTable.appendChild(tr);
  }
}

function decodeFromInput() {
  var pem = document.getElementById("pem").value;
  decode(pem, true);
}

function handleFile(file) {
  var reader = new FileReader();
  reader.onload = function() { decode(reader.result, true); };
  reader.readAsText(file);
}

window.addEventListener("message", function(evt) {
  if (evt.origin != document.location.origin || !evt.data.pem) {
    return;
  }

  decode(evt.data.pem, evt.data.asEndEntity);
}, false);
