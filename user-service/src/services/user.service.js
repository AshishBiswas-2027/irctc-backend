const { config } = require("../config");
const { redis } = require("../config/redis");
const prisma = require("../congig/prisma");
const looger = require("../config/logger");



const getProfile = async (userId) => {

    logger.info("First search user in redis");

    const storedUser = await redis.get(`user:${userId}`);
    if (storedUser) {
        logger.info("Fetched user data from redis");
        return JSON.parse(storedUser);
    }
    logger.info("If user is not in redis fetch from database");
    const userProfile = await prisma.user.findUnique({
        where: {
            id:userId
        }
    })
    logger.info("Exclude password field from the user");
    const { password: _password, ...safeUser } = userProfile;
    logger.info("Store data in redis for future lookups");
    await redis.set(`user:${userId}`, JSON.stringify(safeUser), 'EX', config.REDIS_USER_TTL);
    return safeUser;


    
    
}