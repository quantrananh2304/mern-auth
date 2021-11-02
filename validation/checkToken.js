const jwt = require("jsonwebtoken");
const { secretOrKey } = require("../config/keys");

const checkToken = (req, res, next) => {
    try {
        const token = req.headers.authorization.split(" ")[1];

        // Xác thực token
        jwt.verify(token, secretOrKey, (err, payload) => {
            if (payload) {
                req.user = payload;
                next();
            } else {
                // Nếu token tồn tại nhưng không hợp lệ, server sẽ response status code 401 với msg bên dưới
                res.status(401).send("Unauthorized");
            }
        });
    } catch (err) {
        // Nếu không có token ở header, server sẽ response status code 401 với msg bên dưới
        console.log("err", err);
        res.status(401).send("No token provided");
    }
};

module.exports = { checkToken };
