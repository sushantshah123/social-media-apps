import jwt from "jsonwebtoken"

export const verifyToken = async(req, res, next) => {
    try {
        const token = req.header("Authorization")
        if(!token){
            return res.status(403).json("Access Denied")
        }
        if(token.startsWith("Bearer ")){
           token = token.slice(7, token.length).trimLength()
        }
        const verified = await jwt.verify(token, process.env.JWT_SECRET_KEY)
        req.user = verified
        next()
    } catch (error) {
        res.status(403).json({error: error.msg})
    }
}