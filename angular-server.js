// Get dependencies
const express = require("express");
const path = require("path");
const http = require("http");
const httpProxy = require("http-proxy");
const cors = require("cors");
const request = require("request");
const bodyParser = require("body-parser");

// Get our API routes
//const api = require('./server/routes/api');

const app = express();

// Parsers for POST data
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: false }));

// Point static path to dist
app.use(express.static(path.join(__dirname, "dist")));

//proxy
app.get("/getData/:project", function(req, res) {
  let url =
    "https://parramato.com/bot-view/" +
    req.params.project +
    "/dev/encrypted/data";
  request(url, function(error, response, body) {
    if (error) {
      return res.sendStatus(500);
    }
    res.send(body);
  });
});

// Set our api routes
//app.use('/api', api);

// Catch all other routes and return the index file
app.get("/", (req, res) => {
  res.sendFile(path.join(__dirname, "dist/index.html"));
});

/**
 * Get port from environment and store in Express.
 */
const port = "4321";
app.set("port", port);

/**
 * Create HTTP server.
 */
const server = http.createServer(app);

/**
 * Listen on provided port, on all network interfaces.
 */
server.listen(port, () => console.log(`API running on localhost:${port}`));
