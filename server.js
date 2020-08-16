const express = require('express')
const app = express()
const morgan = require('morgan')
const cors = require('cors')
const mongoose = require('mongoose')
require('dotenv').config()
const bodyParser = require('body-parser')

const authRoutes = require('./routes/auth')
const userRoutes = require('./routes/user')

//app middleware
app.use(morgan('dev'));
app.use(bodyParser.json())
if((process.env.NODE_ENV = 'development')){
    app.use(cors({ origin: `http://localhost:3000` }))
}
app.use('/api',authRoutes)
app.use('/api', userRoutes)

//connect to db
mongoose.connect(process.env.DATABASE, {
    useNewUrlParser: true,
    useFindAndModify: false,
    useUnifiedTopology: true,
    useCreateIndex: true
})
.then(()=> console.log('DB connected'))
.catch(err => console.log(err))


const port = process.env.PORT || 8000
app.listen(port, ()=>{
    console.log(`API running on port ${port}`)
})
