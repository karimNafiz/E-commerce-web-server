const { expressjwt } = require('express-jwt');
const jwt = require('jsonwebtoken');

// Updated function to handle JWT secret more securely using environment variables
function authJwt() {
    const secret = process.env.JWT_SECRET;  // Updated secret handling
    const api = process.env.API_URL;

    return expressjwt({
        secret,
        algorithms: ['HS256'], // Define the algorithm explicitly
    }).unless({
        path: [
            { url: /\/public\/uploads(.*)/, methods: ['GET', 'OPTIONS'] },
            { url: /\/api\/v1\/products(.*)/, methods: ['GET', 'OPTIONS'] },
            { url: /\/api\/v1\/categories(.*)/, methods: ['GET', 'OPTIONS'] },
            { url: /\/api\/v1\/orders(.*)/, methods: ['GET', 'OPTIONS', 'POST'] },
            `${api}/users/login`,
            `${api}/users/register`,
        ]
    });
}

async function isRevoked(req, token) {
    if (!token.payload.isAdmin) {
        return true;  // Revoke token if the user is not an admin
    }
    return false;
}

module.exports = authJwt;
