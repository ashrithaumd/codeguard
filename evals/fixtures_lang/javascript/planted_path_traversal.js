// Planted: a request parameter becomes a filesystem path unchecked.
const fs = require("fs");

function readUpload(req, res) {
  const name = req.params.name;
  fs.readFile("/srv/uploads/" + name, (err, data) => res.send(data));
}

module.exports = { readUpload };
