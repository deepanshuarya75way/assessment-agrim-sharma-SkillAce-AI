const userModel = require('../models/user.model')
const bcrypt = require('bcryptjs')
const jwt = require("jsonwebtoken")
const crypto = require("crypto");
const tokenBlacklistModel = require('../models/blacklist.model');
const accessCookieOptions = {
    httpOnly: true,
    secure: process.env.NODE_ENV === "production",
    sameSite: process.env.NODE_ENV === "production" ? "none" : "lax",
    maxAge: 1* 60 * 1000 // 15 min
};

const refreshCookieOptions = {
    httpOnly:true,
    secure: process.env.NODE_ENV === "production",
    sameSite: process.env.NODE_ENV === "production" ? "none" : "lax",
    maxAge: 7*24*60*60*1000 //7days
}

function hashRefreshToken(token) {
    return crypto.createHash("sha256").update(token).digest("hex");
}

async function createAuthTokens(user){
    const accessToken = jwt.sign(
        {
            id:user._id,
            username:user.username
        },
        process.env.JWT_SECRET,
        {
            expiresIn:"15m"
        }
    );

    const refreshToken = jwt.sign(
        {
            id:user._id,
            type:"refresh"
        },
        process.env.JWT_REFRESH_SECRET,
        {
            expiresIn:"7d"
        }
    );

    user.refreshTokenHash = hashRefreshToken(refreshToken);

    user.refreshTokenExpiresAt= new Date(Date.now()+7*24*60*60*1000);

    await user.save();

    return {
        accessToken,
        refreshToken
    };
}
/**
 * @name registerUserController
 * @description register a new user, expects username, email and password in the requ
 * @access Public
 */

async function registerUserController(req,res){
    const {username,email,password} = req.body;

    if(!username||!email||!password){
        return res.status(400).json({
            message:"Username,email & password are required to register"
        })
    }
    
    const isUserAlreadyExists= await userModel.findOne({
        $or:[{username},{email}]
    })

    if(isUserAlreadyExists){
        return res.status(400).json({
            message:"User already exists"
        })
    }
    const hash = await bcrypt.hash(password,10);

    const user = await userModel.create({
        username,
        email,
        password:hash
    })

   const {accessToken,refreshToken}= await createAuthTokens(user);

   res.cookie("token",accessToken,accessCookieOptions);

   res.cookie("refreshToken",refreshToken,refreshCookieOptions);

   res.status(201).json({
    message:"User registered Successfully",
   user: {
    id: user._id,
    username: user.username,
    email: user.email,
    hasApiKey: !!user.geminiApiKey
}
   })
}

/**
 * @name loginUserController
 * @description login a user, expects email and password in the request body
 * @access Public
 */

async function loginUserController(req,res){
    const{email,password}=req.body;

    const user = await userModel.findOne({email});

    if(!user){
        return res.status(400).json({
            message:"Invalid email or password"
        })
    }

    const isPasswordValid= await bcrypt.compare(password,user.password)

    if(!isPasswordValid){
        return res.status(400).json({
            message:"Passowrd is incorrect"
        })
    }

    const {accessToken,refreshToken}= await createAuthTokens(user);

   res.cookie("token",accessToken,accessCookieOptions);

   res.cookie("refreshToken",refreshToken,refreshCookieOptions);


   res.status(201).json({
    message:"User LoggedIn Successfully",
    user: {
    id: user._id,
    username: user.username,
    email: user.email,
    hasApiKey: !!user.geminiApiKey
}
   })
}

async function refreshTokenController(req,res){

    const refreshToken = req.cookies.refreshTokeen;

    if(!refreshToken){
        return res.status(401).json({
            message:"Refresh Token not provided"
        });
    }

    try{
        const decoded = jwt.verify(
            refreshToken,
            process.env.JWT_REFRESH_SECRET
        );

        if(decoded.type!=="refresh"){
            return res.status(401).json({
                message:"Invalid Refresh token"
            });
        }

        const user = await userModel.findById(decoded.id);

        if(!user){
            return res.status(401).json({
                message:"User Not found"
            })
        }

        if(
            !user.refreshTokenHash||!user.refreshTokenExpiresAt||user.refreshTokenExpiresAt< new Date()
        ){
            return res.status(401).json({
                message:"Refresh Token expired or revoked"
            })
        }

        const incominghash = hashRefreshToken(refreshToken);
        if(incominghash!==user.refreshTokenHash){
            return res.status(401).json({
                message: "Invalid Refresh Token"
            })
        }

        const{
            accessToken,
            refreshToken : newRefreshTokenn}= await createAuthTokens(user);
        
            res.cookie("token",accessToken,accessCookieOptions);

            res.cookie(
                "refreshToken",
                newRefreshToken,
                refreshCookieOptions
            );

            return res.status(200).json({
                message:"Access token refreshed"
            });
    }
    catch(error){
        return res.status(401).json({
            message: "Invalid or expired refresh token"
        })
    }
}
/**
 * @name logoutUserController
 * @description clear token from user cookie and add the token in blacklist
 * @access public
 */

async function logoutUserController(req,res){
    const token = req.cookies.token;
    const refreshToken = req.cookies.refreshToken;
    let userId = null;

    if(token){
        try{
        const decoded = jwt.verify(token,process.env.JWT_SECRET);
        userId = decoded.id;
        await tokenBlacklistModel.create({
            token
        });
        }catch(error){

        }
    }
        if (!userId&&refreshToken){
            try{
               const decoded = jwt.verify(refreshToken,process.env.JWT_REFRESH_SECRET);
               userId= decoded.id;
            }catch(error){

            }
        }
            if (userId){
                await userModel.findByIdAndUpdate(userId,
                    {
                        refreshTokenHash:null,
                        refreshTokenExpiresAt:null
                    }
                );
            }

            res.clearCookie("token",accessCookieOptions);
            res.clearCookie("refreshToken",refreshCookieOptions);
            return res.status(200).json({
                message:"user logged out successfully"
            });

}

/**
 * @name getMeController
 * @description get the current logged in user details.
 * @access private
 */


async function getMeController(req,res){
    const user = await userModel.findById(req.user.id)
 res.status(200).json({
    message:"User details fetched sucessfully",
  user: {
    id: user._id,
    username: user.username,
    email: user.email,
    hasApiKey: !!user.geminiApiKey
}
})

}

async function saveApiKeyController(req, res) {

    const { apiKey } = req.body;

    if (!apiKey) {
        return res.status(400).json({
            message: "API Key is required"
        });
    }

    await userModel.findByIdAndUpdate(
        req.user.id,
        {
            geminiApiKey: apiKey
        }
    );

    return res.status(200).json({
        message: "API Key saved successfully"
    });
}
module.exports={registerUserController,loginUserController,logoutUserController,refreshTokenController, getMeController, saveApiKeyController}