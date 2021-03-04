const express = require('express');
const bodyParser = require('body-parser');

const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
const cors = require('cors');

// // NEW: MySQL database driver
const mysql = require('mysql2/promise');

const app = express();


// We import and immediately load the `.env` file
require('dotenv').config();

const port = process.env.PORT;

const pool = mysql.createPool({
  host: process.env.DB_HOST,
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME
});

//The `use` functions are the middleware - they get called before an endpoint is hit
app.use(async function mysqlConnection(req, res, next) {
  try {
    req.db = await pool.getConnection();
    req.db.connection.config.namedPlaceholders = true;

    // Traditional mode ensures not null is respected for unsupplied fields, ensures valid JavaScript dates, etc.
    await req.db.query('SET SESSION sql_mode = "TRADITIONAL"');
    await req.db.query(`SET time_zone = '-8:00'`);

    await next();

    req.db.release();
  } catch (err) {
    // If anything downstream throw an error, we must release the connection allocated for the request
    console.log(err)
    if (req.db) req.db.release();
    throw err;
  }
});

app.use(cors());

app.use(bodyParser.json());

// Public endpoints - the user doesn't need to be authenticated in order to reach them
app.post('/register', async function (req, res) {
  try {
    let user;
    // Hashes the password and inserts the info into the `user` table
    await bcrypt.hash(req.body.password, 10).then(async hash => {
      try {
        [user] = await req.db.query(`
          INSERT INTO user (email, fname, lname, password)
          VALUES (:email, :fname, :lname, :password);
        `, {
          email: req.body.email,
          fname: req.body.fname,
          lname: req.body.lname,
          password: hash
        });

      } catch (error) {
        console.log('error', error)
      }
    });

    const encodedUser = jwt.sign(
      {
        userId: user.insertId,
        ...req.body
      },
      process.env.JWT_KEY
    );

    res.json(encodedUser);

  } catch (err) {
    console.log('err', err)
  }
})


app.post('/auth', async function (req, res) {
  try {
    const [[user]] = await req.db.query(`
      SELECT * FROM user WHERE email = :email
    `, {
      email: req.body.email
    });
    if (!user) {
      res.json('Email not found')
    }

    const userPassword = `${user.password}`
    const compare = await bcrypt.compare(req.body.password, userPassword)

    if (compare) {
      const payload = {
        userId: user.id,
        email: user.email,
        fname: user.fname,
        lname: user.lname,
        role: 4
      }

      const encodedUser = jwt.sign(payload, process.env.JWT_KEY);

      res.json(encodedUser)
    } else {
      res.json('Password not found')
    }
  } catch (err) {
    console.log('Error in /auth', err)
  }
})


// Jwt verification checks to see if there is an authorization header with a valid jwt in it.
app.use(async function verifyJwt(req, res, next) {

  if (!req.headers.authorization) {
    throw (401, 'Invalid authorization');
  }

  const [scheme, token] = req.headers.authorization.split(' ');

  if (scheme !== 'Bearer') {
    throw (401, 'Invalid authorization');
  }

  try {
    const payload = jwt.verify(token, process.env.JWT_KEY);

    req.user = payload;
  } catch (err) {
    if (err.message && (err.message.toUpperCase() === 'INVALID TOKEN' || err.message.toUpperCase() === 'JWT EXPIRED')) {

      req.status = err.status || 500;
      req.body = err.message;
      req.app.emit('jwt-error', err, req);

    } else {

      throw ((err.status || 500), err.message);
    }
    console.log(err)
  }

  await next();
})

// These are the private endpoints, they require jwt authentication. When a request is made it goes to one of these functions after it goes through the middleware.
// Then a response is set an returned (like `res.json(cars)`)

app.get('/:id', async function (req, res) {

  const [[phones]] = await req.db.query(
    `SELECT description FROM products WHERE id = :id`,
    {
      id: req.params.id
    }
  );
  res.json(phones);
})

app.post('/', async function (req, res) {
  try {
    let product = await req.db.query(
      `INSERT INTO products (
          brands, 
          description,
          product_price,
          date_created
          ) VALUES (
            :brands,
            :description,
            :product_price,
            NOW()
          )`,
      {
        brands: req.body.product.brand,
        description: req.body.product.name,
        product_price: req.body.product.price
      }
    );

    res.json(product)
  } catch (err) {
    console.log('post /', err)
  }
})

app.post('/shipping', async function (req, res) {
  try {
    let customerData = await req.db.query(
      `INSERT INTO shipping_address (
          name, 
          address,
          date_created
          ) VALUES (
            :name,
            :address,
            NOW()
          )`,
      {
        name: req.body.customerData.name,
        address: req.body.customerData.address,

      }
    );

    res.json(customerData)
  } catch (err) {
    console.log('post /shipping', err)
  }
})

app.post('/notify', async function (req, res) {
  try {
    let saleAlert = []
    req.body.saleAlert.forEach(async alert => {
      alert = await req.db.query(
        `INSERT INTO message_center (
          subject, 
          message,
            date_created
          ) VALUES (
            :subject,
            :message,
            NOW()
          )`,
        {
          subject: alert.subject,
          message: alert.message

        }
      );

      saleAlert.push(alert)

    })
    res.json({
      message: 'Alert added successfully',
      data: saleAlert
    });
  } catch (err) {
    console.log('post /notify', err)
  }
});

app.put('/:id', async function (req, res) {

  const [phones] = await req.db.query(`
    UPDATE products SET description = :description WHERE id = :id
  `, {
    description: req.body.model,
    id: req.params.id
  });

  res.json(phones);
})

app.delete('/:id', async function (req, res) {
  const [phones] = await req.db.query(`
    DELETE FROM products WHERE id = :id
  `, {
    id: req.params.id
  });

  res.json(phones);
})

app.listen(port, () => console.log(`Demo app listening at http://localhost:${port}`));
