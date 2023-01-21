require('rootpath')();
const express = require('express');
const app = express();
const bodyParser = require('body-parser');
const cookieParser = require('cookie-parser');
const cors = require('cors');
const errorHandler = require('_middleware/error-handler');
require('dotenv').config({ path: './.env' });

global.__basedir = __dirname;
var corsOptions = {
  origin: '	https://resumix.netlify.app',
  // origin: 'http://localhost:3000',
};
app.use(cors(corsOptions));

app.use(
  bodyParser.urlencoded({
    limit: '50mb',
    parameterLimit: 100000,
    extended: true,
  })
);
app.use(
  bodyParser.json({
    limit: '50mb',
  })
);

// app.use(express.static(process.env.STATIC_DIR));
app.use(cookieParser());

// allow cors requests from any origin and with credentials
app.use(
  cors({
    origin: (origin, callback) => callback(null, true),
    credentials: true,
  })
);

// api routes
app.use('/accounts', require('./accounts/accounts.controller'));

app.use('/resume', require('./resume/resume.controller'));

// global error handler
app.use(errorHandler);

// start server
const port =
  process.env.NODE_ENV === 'production' ? process.env.PORT || 80 : 4000;
app.listen(port, () => {
  console.log('Server listening on port ' + port);
});
