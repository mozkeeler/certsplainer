let pem = "-----BEGIN CERTIFICATE-----" +
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
  let result = "";
  rdn.attributes.forEach(function(attribute) {
    if (attribute.shortName) {
      let spacer = result.length ? ", " : "";
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
  let result = "";
  altNames.altNames.forEach(function(altName) {
    let spacer = result.length ? ", " : "";
    result += spacer + formatAltName(altName);
  });
  return result;
}

function clearFields() {
  for (let id of ["version", "serialNumber", "issuer", "subject", "notBefore",
                  "notAfter", "subjectAltNames", "signatureAlgorithm",
                  "keySize", "exponent"] ) {
    setField(id, "");
    unsetViolation(id);
  }
}

function decode(pem) {
  clearFields();

  let cert = null;
  try {
    cert = forge.pki.certificateFromPem(pem);
  } catch (e) {}
  // Try with the BEGIN/END wrappers if the above failed
  if (!cert) {
    cert = forge.pki.certificateFromPem("-----BEGIN CERTIFICATE-----" + pem +
                                        "-----END CERTIFICATE-----");
  }
  setField("version", cert.version + 1);
  if ((cert.version + 1) != 3) {
    setViolation("version");
  }
  setField("serialNumber", cert.serialNumber);
  setField("issuer", formatRDN(cert.issuer));
  setField("subject", formatRDN(cert.subject));
  setField("notBefore", cert.validity.notBefore);
  setField("notAfter", cert.validity.notAfter);
  if ((cert.validity.notAfter - cert.validity.notBefore) /
      (1000 * 3600 * 24 * 366) > 5) {
    setViolation("notBefore");
    setViolation("notAfter");
  }
  setField("subjectAltNames",
           formatSubjectAltNames(cert.getExtension({name: 'subjectAltName'})));
  if (!cert.getExtension({name: 'subjectAltName'})) {
    setViolation("subjectAltNames");
  }
  setField("signatureAlgorithm", forge.pki.oids[cert.signatureOid]);
  if (forge.pki.oids[cert.signatureOid] == "sha1WithRSAEncryption") {
    setViolation("signatureAlgorithm");
  }
  setField("keySize", cert.publicKey.n.bitLength());
  if (cert.publicKey.n.bitLength() <= 1024) {
    setViolation("keySize");
  }
  setField("exponent", cert.publicKey.e.toString());
  if (cert.publicKey.e.toString() == "3") {
    setViolation("exponent");
  }
  setField("pem", forge.pki.certificateToPem(cert));
}

function decodeFromInput() {
  let pem = document.getElementById("pem").value;
  decode(pem);
}

function handleFile(file) {
  let reader = new FileReader();
  reader.onload = function() { decode(reader.result); };
  reader.readAsText(file);
}

decode(location.search ? location.search.substring(1) : pem);
