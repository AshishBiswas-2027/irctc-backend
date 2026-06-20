const express = require('express');
const { getUserContext } = require('../middlewares/getUserContext.middleware');
const { getProfile , updateProfile , deleteProfile } = require('../controllers/user.controller');

const router = express.Router();

//===========BEFORE API GATEWAY IMPLEMENTATION=========
//requireAuth acts as a middleware as get-profile is a private route which can only be accessed after login
// router.get("/get-profile", requireAuth, getProfile);


//============AFTER API GATEWAY IMPLEMENTATION==============

router.get('/profile', getUserContext, getProfile);

router.put('/profile', getUserContext, updateProfile);

router.delete('/delete', getUserContext, deleteProfile);

module.exports = router;