const express = require('express');
const { requireAuth } = require('../middlewares/auth.middleware');
const { getProfile } = require('../controllers/user.controller');

const router = express.Router();

//requireAuth acts as a middleware as get-profile is a private route which can only be accessed after login 
router.get("/get-profile", requireAuth, getProfile);

module.exports = router;