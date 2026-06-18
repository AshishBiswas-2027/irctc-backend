const crypto = require("crypto");

function getDeviceFingerprint(req) {
     const userAgent = req.headers["user-agent"] || "";
     const ip = req.ip || "";
     const accept = req.headers["accept"] || "";

     const raw = `${userAgent}|${ip}|${accept}`;

     return crypto
          .createHash("sha256")
          .update(raw)
          .digest("hex")
          .slice(0, 16); // short device id
}

module.exports = getDeviceFingerprint;
//non critical application hai isiliye multiple devices se login ho sakta hai 
//ye device id return karega
//kyu ki same mail se more than one device chal sakta hai toh sabka session alaga alag hoga 