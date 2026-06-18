const { BadRequestError, UnauthorizedError } = require("../utils/error");
const asyncHandler = require('../utils/asyncHandler');
const {config} = require('../config');
const authService = require('../services/auth.service');
const getDeviceFingerprint = require("../utils/deviceFingerPrint");
const logger = require("../config/logger");
const { http } = require("winston");
const prisma = require('../config/prisma');
const { generateRefreshToken } = require("../utils/auth");

//catches info from frontend 
//if not present then error 
//if password != confirm password then error
//authservice me info bhejkar otpsessionid generate karte hai aur usko cookie me save karte hai 
exports.sendOTP = asyncHandler(async(req, res) =>{
     const {firstName, lastName, email, password, confirmPassword} = req.body;
     if(!firstName || !lastName || !email || !password || !confirmPassword){
          throw new BadRequestError("All fields are mandatory");
     }

     if(password !== confirmPassword){
          throw new BadRequestError("Password mismatch");
     }

     const {otpSessionId} = await authService.sendOTP(firstName, lastName, email, password);
     res.cookie("otp_session", otpSessionId, {
          httpOnly: true,
          secure: true,
          sameSite: "strict",
          maxAge: config.OTP_TTL * 1000
     }).status(200).json({
          success: true,
          message: "OTP sent successfully"
     })
})


//otp milega frontend se 
// cookie se otpsession id find kar lenge 
//kuch b gayab hai to error 
//fir services me auth service k method ko call kar denge jo sara business logic hold karti hai 
//otp verify ho jayega toh user return hoga waha se toh fir show kar denge 

exports.verifyOTP = asyncHandler(async(req, res) =>{
     const {otp} = req.body;
     const otpSessionId = req.cookies.otp_session;

     if(!otp || !otpSessionId){
          throw new BadRequestError("OTP or OTPSession is missing")
     }

     const user = await authService.verifyOTP(otp, otpSessionId);
     res.clearCookie("otp_session");
     return res.status(201).json({
          success: true,
          message: "User Account created successfully",
          data: user
     })
})

//frontend se email pass lega 
//device id fetch karega 
//authservice me bhej k refresh aur access token generate karwayega aur cookie me set kar dega 
//aur login kar dega
exports.login = asyncHandler(async(req, res) =>{
     const {email, password} = req.body;
     if(!email || !password){
          throw new BadRequestError("Email and Password are required")
     }
     const deviceId = getDeviceFingerprint(req);
     const {accessToken, refreshToken, loggedInUser} = await authService.login(email, password, deviceId);
     res.cookie("accessToken", accessToken, {
          httpOnly: true,
          secure: true,
          sameSite: "strict",
          maxAge: config.ACCESS_TOKEN_EXP_SEC * 1000
     })
     res.cookie("refreshToken", refreshToken, {
          httpOnly: true,
          secure: true,
          sameSite: "strict",
          maxAge: config.REFRESH_TOKEN_EXP_SEC * 1000
     }).status(200).json({
          success: true,
          message: "Logged in successfully",
          loggedInUser
     })
})


//naya access aur refreshtoken generate karta hai 
//cookie se lete hai tokens - if not presetn error 
//if present - to service ko de denge aur naya bana kar de degag wo 
//fir waapas naya tokens cookie me store kar denge 
exports.rotateRefreshToken = asyncHandler(async(req, res) =>{
     const refreshToken = req.cookies.refreshToken;
     if(!refreshToken){
          throw new UnauthorizedError("Refresh token is missing", "LOGIN AGAIN")
     }
     const deviceId = getDeviceFingerprint(req);
     const {newAccessToken, newRefreshToken} = await authService.rotateRefreshToken(refreshToken, deviceId);
     res.cookie("accessToken", newAccessToken, {
          httpOnly: true,
          secure: true,
          sameSite: "strict",
          maxAge: config.ACCESS_TOKEN_EXP_SEC * 1000
     })
     res.cookie("refreshToken", newRefreshToken, {
          httpOnly: true,
          secure: true,
          sameSite: "strict",
          maxAge: config.REFRESH_TOKEN_EXP_SEC * 1000
     }).status(200).json({
          success: true,
          message: "Access and Refresh token reissued"
     })
})


//controllers incoming http request ko correct business logic me route karta hai 


//id token fetch karenge frontend se 
// if not found- error 
// if found - verify karenge auth service ko bhej k where the real business logic is present

exports.verifyGoogleIdToken = asyncHandler(async(req, res) =>{
     const {idToken} = req.body;
     if(!idToken){
          throw new BadRequestError("Invalid Google ID Token", "INVALID TOKEN")
     }

     const deviceId = getDeviceFingerprint(req);
     
     const {accessToken, refreshToken, loggedInUser} = await authService.verifyGoogleIdToken(idToken, deviceId);
     
     res.cookie("accessToken", accessToken, {
          httpOnly: true,
          secure: true,
          sameSite: "strict",
          maxAge: config.ACCESS_TOKEN_EXP_SEC * 1000
     })
     res.cookie("refreshToken", refreshToken, {
          httpOnly: true,
          secure: true,
          sameSite: "strict",
          maxAge: config.REFRESH_TOKEN_EXP_SEC * 1000
     }).status(200).json({
          success: true,
          message: "Logged in successfully",
          loggedInUser
     })
})