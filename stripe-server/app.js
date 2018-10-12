const bodyParser    = require('body-parser')
const cookieParser  = require('cookie-parser')
const express       = require('express')
const mongoose      = require('mongoose')
const logger        = require('morgan')
const path          = require('path')
const session       = require("express-session")
const MongoStore    = require('connect-mongo')(session)
const flash         = require("connect-flash")
const cors          = require('cors')

mongoose
  .connect('mongodb://localhost/stripe-server', {useNewUrlParser: true})
  .then(x => {
    console.log(`Connected to Mongo! Database name: "${x.connections[0].name}"`)
  })
  .catch(err => {
    console.error('Error connecting to mongo', err)
  })

const app = express()

// Middleware Setup
app.use(logger('dev'))
app.use(bodyParser.json())
app.use(bodyParser.urlencoded({ extended: false }))
app.use(cookieParser())
app.use(cors({
  credentials: true,
  origin: true
}))
      
// Enable authentication using session + passport
app.use(session({
  secret: 'irongenerator',
  resave: true,
  saveUninitialized: true,
  store: new MongoStore( { mongooseConnection: mongoose.connection })
}))
app.use(flash())
require('./passport')(app)
    

const index = require('./routes/index')
app.use('/', index)

const authRoutes = require('./routes/auth')
app.use('/auth', authRoutes)

const PORT = process.env.PORT || 3000

app.listen(PORT, console.log('server running 🚀'))

module.exports = app