const express = require("express");
const bodyParser = require("body-parser"); 
const { logger, Middlewarelogs } = require("./services/logger/logger.js");
const routes = require('./routes/routes.js'); 
const helmet = require('helmet');

require("dotenv").config();

const app = express();
const PORT = process.env.SERVER_PORT || 3450;

app.use(helmet());
app.use(Middlewarelogs);
app.use(bodyParser.json()); 
app.use(bodyParser.urlencoded({ extended: true })); 

app.use((err, req, res, next) => {
  logger.error(`Error occurred: ${err.message}`);
  res.status(500).send("Something went wrong!");
});

app.use('/', routes);

app.listen(PORT, '0.0.0.0', () => {
  logger.info(`Server started and running on PORT http://localhost:${PORT} at ${new Date()}`);
});

process.on('SIGTERM', () => {
  logger.info('SIGTERM signal received: closing HTTP server')
  app.close(() => {
    logger.info('HTTP server closed')
  })
})