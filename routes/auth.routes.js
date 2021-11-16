const router = require("express").Router()
const UserModel = require('../models/User.model')
const bcrypt = require('bcryptjs')

router.get('/signin', (req, res, next)=>{
    res.render('auth/signin.hbs')
})

router.get('/signup', (req, res, next)=>{
    res.render('auth/signup.hbs')
})

router.post('/signup', (req,res,next) => {
    const {username, password} = req.body

    if (username == '' || password == ''){
        res.render('auth/signup.hbs', {error: 'Please enter all fields'})
        return;
    }

    let passwordRegExp = /^(?=.*[A-Za-z])(?=.*\d)[A-Za-z\d]{8,}$/
    if(!passwordRegExp.test(password)){
        res.render('auth/signup.hbs' , {error: 'Please enter the minimum 8 characters, at least one letter and one number for your password!'})
        return;
    } 

    let usernameRegExp = /^[a-zA-Z0-9](_(?!(\.|_))|\.(?!(_|\.))|[a-zA-Z0-9]){6,18}[a-zA-Z0-9]$/
    if(!usernameRegExp.test(username)){
        res.render('auth/signup.hbs', {error: 'Your username should countain only letters and numbers and between 6-18 characters!'})
        return;
    }

    let salt = bcrypt.genSaltSync(12)
    let hash = bcrypt.hashSync(password, salt);

    UserModel.create({username, password:hash})
    .then(()=>{
        res.redirect('/')
    })
    .catch((error)=>{
        next(error)
    })
})

router.post('/signin', (req, res, next)=>{
    const {username, password} = req.body 

    UserModel.find({username})
    .then((userResponse)=>{
        if(userResponse.length){
            let userObj = userResponse[0]

            let isMatching = bcrypt.compareSync(password, userObj.password);

            if(isMatching){
                req.session.myProperty = userObj
                res.redirect('/profile')
            } else {
                res.render('auth/signin.hbs' , {error: 'Password not matching'})
                return;
            }
        } else {
            res.render('auth/signin', {error: 'User does not exist'})
            return;
        }
    })
    .catch((error)=>{
        next(error)
    })
})

const checkLogged = (req, res, next) => {
    if(req.session.myProperty){
        next()
    } else {
        res.redirect('/signin')
    }
}

router.get('/profile', checkLogged, (req, res, next) => {
    let userObj = req.session.myProperty
    res.render('auth/profile.hbs', {name: userObj.username})
})

router.get('/main', checkLogged,(req, res, next) => {
        res.render('auth/main.hbs')
})

router.get('/private', checkLogged, (req, res, next) => {
    res.render('auth/private.hbs')
})


router.get('/logout', checkLogged, (req, res, next) => {
    req.session.destroy()
    res.redirect('/signin')
})




module.exports = router;