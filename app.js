require('dotenv').config()
const express = require('express')
const mongoose = require('mongoose')
const brcypt = require('bcrypt')
const jwt = require('jsonwebtoken')


const app = express()



// Cinfig json 
app.use(express.json())



//MODELS
const User = require('./models/User')



// PUCLIC ROUTE
app.get('/', (req, res) => {
    res.status(200).json({ msg: "Bem vindo a nossa API" })
})



// PRIVATE ROUTE
app.get('/user/:id', async (req, res) => {
    const id = req.params.id



    //check if user exists
    const user = await User.findById(id).catch(e => res.status(402).json({ msg: 'erro ao encontrar usuário' }))

    if (!user) {
        return res.status(404).json({ msg: 'usuário não encontrado' })
    }

    res.status(200)
})



// REGISTER USER
app.post('/auth/register', async (req, res) => {

    const { name, email, password, confirmpassword } = req.body



    // validations 
    if (!name) {
        return res.status(422).json({ msg: 'O nome é obrigatório' })
    }
    if (!email) {
        return res.status(422).json({ msg: 'O email é obrigatório' })
    }
    if (!password) {
        return res.status(422).json({ msg: 'O password é obrigatório' })
    }
    if (password != confirmpassword) {
        return res.status(422).json({ msg: "as senhas não conferem" })
    }



    // CHECK IF USER CHECKLIST
    const userExists = await User.findOne({ email: email })
    if (userExists) {
        return res.status(422).json({ msg: "por favor ultilize outro email!" })
    }



    //CREATE  PASSWORD
    const salt = await brcypt.genSalt(12)
    const passwordHash = await brcypt.hash(password, salt)



    // CREATE USER
    const user = new User({
        name,
        email,
        password: passwordHash
    })

    try {
        await user.save()
        res.status(201).json({ msg: 'usuário criado com sucesso' })
    } catch (e) {
        console.log(e)
        res.status(500).json({ msg: "aconteu um erro no servidor, volte novamente mais tarde" })
    }
})

app.post('/auth/login', async (req, res) => {
    const { email, password } = req.body



    // VALIDATION 
    if (!email) {
        return res.status(422).json({ msg: 'O email é obrigatório' })
    }
    if (!password) {
        return res.status(422).json({ msg: 'O password é obrigatório' })
    }


    //CHECK IF USER EXIST
    const user = await User.findOne({ email: email })
    if (!user) {
        return res.status(404).json({ msg: "usuário não encontrado, verifique o email!" })
    }



    // CHECK IF PAWWORD MATCH
    const checkpassword = await brcypt.compare(password, user.password)

    if (!checkpassword) {
        return res.status(422).json({ msg: 'Senha Incorreta!' })
    }

    try {

        const secret = process.env.SECRET
        const token = jwt.sign({
            id: user._id,
        }, secret)

        res.status(200).json({ msg: 'usuário logado com sucesso!', token })

    } catch (e) {
        console.log(e)
        res.status(500).json({ msg: "aconteu um erro no servidor, volte novamente mais tarde" })
    }


})

//CREDENTIALS
const dbUser = process.env.DB_USER
const dbPass = process.env.DB_PASS


mongoose.set('strictQuery', false)
mongoose.connect(`mongodb+srv://${dbUser}:${dbPass}@cluster0.km1r1l7.mongodb.net/?retryWrites=true&w=majority`).then(() => {
    app.listen(3000, () => {
        console.log('app rodando na porta 3000')
    })

}).catch(e => console.log(e))
