const express = require("express");

const app = express();

app.get("/", (req, res) => {
    res.json({
        message: "Backend berhasil berjalan di Vercel!"
    });
});

module.exports = app;