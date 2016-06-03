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

// special-case msSGC and nsSGC for display purposes
function formatEKUOID(ekuOID) {
  if (ekuOID == "1.3.6.1.4.1.311.10.3.3") {
    return "msSGC";
  }
  if (ekuOID == "2.16.840.1.113730.4.1") {
    return "nsSGC";
  }
  return ekuOID;
}

function formatExtKeyUsage(extension) {
  var skip = ["id", "critical", "value", "name"];
  var output = "";
  Object.keys(extension).forEach(function(key) {
    if (skip.indexOf(key) != -1) {
      return;
    }
    if (extension[key]) {
      output += (output ? ", " : "") + formatEKUOID(key);
    }
  });
  return output;
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

function forgeRDNArrayToString(rdn) {
  var output = "";
  for (var i in rdn) {
    output = output + "/" + rdn[i].shortName + "=" + rdn[i].value;
  }
  return output;
}

function formatCRLDistributionPoints(extension) {
  var distributionPoints = ASN1.decode(byteStringToBytes(extension.value));
  var output = "";
  for (var i = 0; i < distributionPoints.sub.length; i++) {
    var distributionPointData = distributionPoints.sub[i];
    var distributionPoint = distributionPointData.sub[0];
    for (var j = 0; j < distributionPoint.sub[0].sub.length; j++) {
      var name = distributionPoint.sub[0].sub[j];
      // This basically assumes this is an RDN - whether or not it actually
      // is should probably be verified by checking an ASN.1 tag or something.
      if (name.sub) {
        var data = "";
        for (var k = name.sub[0].posStart(); k < name.sub[0].posEnd(); k++) {
          data += String.fromCharCode(name.sub[0].stream.enc[k]);
        }
        var asn1 = forge.asn1.fromDer(data);
        output += (output ? ", " : "") +
               forgeRDNArrayToString(forge.pki.RDNAttributesAsArray(asn1));
      } else {
        output += (output ? ", " : "") + name.content();
      }
    }
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
  var result = "";
  var nameConstraints = ASN1.decode(byteStringToBytes(extension.value));
  var permittedSubtrees = nameConstraints.sub[0];
  if (permittedSubtrees && permittedSubtrees.tag.tagNumber == 0) {
    var permittedOutput = "";
    for (var i = 0; i < permittedSubtrees.sub.length; i++) {
      var permittedSubtree = permittedSubtrees.sub[i];
      permittedOutput += (permittedOutput ? ", " : "") +
                         permittedSubtrees.sub[i].sub[0].content();
    }
    result += "permitted: " + permittedOutput;
  }
  var excludedSubtrees =
    (permittedSubtrees && permittedSubtrees.tag.tagNumber == 0
      ? nameConstraints.sub[1]
      : permittedSubtrees);
  if (excludedSubtrees && excludedSubtrees.tag.tagNumber == 1) {
    var excludedOutput = "";
    for (var i = 0; i < excludedSubtrees.sub.length; i++) {
      excludedOutput += (excludedOutput ? ", " : "") +
                         excludedSubtrees.sub[i].sub[0].content();
    }
    result += (result ? "; " : "") + "excluded: " + excludedOutput;
  }
  return result;
}

function formatAuthorityKeyIdentifier(extension) {
  var authorityKeyIdentifier = ASN1.decode(byteStringToBytes(extension.value));
  return authorityKeyIdentifier.sub[0].content().replace(/\(20 byte\)\W/, "")
                                                .toLowerCase();
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
      case "authorityKeyIdentifier": return formatAuthorityKeyIdentifier(extension);
      case "cRLDistributionPoints": return formatCRLDistributionPoints(extension);
      case "certificatePolicies":
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

function hashPEM(pem, algorithm) {
  var der = atob(pem.replace(/-----BEGIN CERTIFICATE-----/, "")
                    .replace(/-----END CERTIFICATE-----/, "")
                    .replace(/[\r\n]/g, ""));
  var digest;
  if (algorithm == "sha1") {
    digest = forge.md.sha1.create();
  } else if (algorithm == "sha256") {
    digest = forge.md.sha256.create();
  } else {
    throw "unsupported hash algorithm: " + algorithm;
  }
  digest.start();
  digest.update(der);
  var hash = digest.digest();
  return hash.toHex().replace(/.{2}/g, "$&:").slice(0, -1).toUpperCase();
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
    pem = "-----BEGIN CERTIFICATE-----" + pem + "-----END CERTIFICATE-----";
    cert = forge.pki.certificateFromPem(pem);
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
  if ("n" in cert.publicKey) {
    setField("keySize", cert.publicKey.n.bitLength());
    setField("exponent", cert.publicKey.e.toString());
    setField("curve", "");
    document.getElementById("keySizeLabel").setAttribute("class", "");
    document.getElementById("exponentLabel").setAttribute("class", "");
    document.getElementById("curveLabel").setAttribute("class", "hidden");
  } else {
    setField("keySize", "");
    setField("exponent", "");
    setField("curve", forge.pki.oids[cert.publicKey.curve]);
    document.getElementById("keySizeLabel").setAttribute("class", "hidden");
    document.getElementById("exponentLabel").setAttribute("class", "hidden");
    document.getElementById("curveLabel").setAttribute("class", "");
  }

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
        forge.pki.oids[cert.signatureOid] != "sha512WithRSAEncryption" &&
        forge.pki.oids[cert.signatureOid] != "ecdsaWithSHA256" &&
        forge.pki.oids[cert.signatureOid] != "ecdsaWithSHA384") {
      setViolation("signatureAlgorithm");
    }
    if ("n" in cert.publicKey && cert.publicKey.n.bitLength() <= 1024) {
      setViolation("keySize");
    }
    if ("e" in cert.publicKey && cert.publicKey.e.toString() == "3") {
      setViolation("exponent");
    }
  }
  document.getElementById("sha1hash").textContent = hashPEM(pem, "sha1");
  document.getElementById("sha256hash").textContent = hashPEM(pem, "sha256");
  document.getElementById("pem").value = pem;

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
