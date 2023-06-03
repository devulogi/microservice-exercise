const express = require('express');
const cookieParser = require('cookie-parser');
const dotenv = require('dotenv');
const morgan = require('morgan');
const cors = require('cors');

const rootRouter = require('./routes/root.routes');

dotenv.config();

const app = express();
app.use(cors());
app.use(express.json());
app.use(cookieParser());

app.use('/api', rootRouter);

app.use((err, req, res, next) => {
  res.status(err.statusCode || 500).send({
    description: err.message || 'Internal server error',
    hint: err.hint || 'Please contact the administrator',
    metadata: {
      timestamp: new Date().toISOString(),
      request: {
        method: req.method,
        url: req.originalUrl,
        payload: req.body
      }
    },
    error: {
      info: err.info || null,
      stack: err.stack,
    }
  });
});

app.use((req, res) => {
  res.status(404).send({
    error: 'Not found',
    alert: 'The requested resource was not found'
  });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Server started on port ${PORT}`));
