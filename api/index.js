const express = require("express");
const { createClient } = require("@supabase/supabase-js");
require("dotenv").config();
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");

const app = express();

app.use(express.json());

const supabase = createClient(
    process.env.SUPABASE_URL,
    process.env.SUPABASE_SECRET_KEY
);


app.get("/", (req, res) => {
    res.json({
        message: "Backend berhasil berjalan di Vercel!"
    });
});

const verifyToken = (req, res, next) => {
    const authHeader = req.headers.authorization;

    if (!authHeader) {
        return res.status(401).json({
            success: false,
            message: "Token tidak ditemukan"
        });
    }

    const token = authHeader.split(" ")[1];

    try {
        const decoded = jwt.verify(
            token,
            process.env.JWT_SECRET
        );

        req.user = decoded;

        next();
    } catch (error) {
        return res.status(401).json({
            success: false,
            message: "Token tidak valid atau sudah expired"
        });
    }
};

app.get("/api/test-db", async (req, res) => {
    const { data, error } = await supabase
        .from("users")
        .select("*");

    if (error) {
        return res.status(500).json({
            success: false,
            message: "Gagal terhubung ke database",
            error: error.message
        });
    }

    res.json({
        success: true,
        message: "Berhasil terhubung ke Supabase!",
        data: data
    });
});

app.post("/api/register", async (req, res) => {
    const { name, email, password } = req.body;

    // Validasi input kosong
    if (!name || !email || !password) {
        return res.status(400).json({
            success: false,
            message: "Name, email, dan password wajib diisi"
        });
    }

    // Validasi panjang password
    if (password.length < 6) {
        return res.status(400).json({
            success: false,
            message: "Password minimal 6 karakter"
        });
    }

    // Validasi format email sederhana
    if (!email.includes("@")) {
        return res.status(400).json({
            success: false,
            message: "Format email tidak valid"
        });
    }

    // Cek apakah email sudah terdaftar
    const { data: existingUser, error: checkError } = await supabase
        .from("users")
        .select("id")
        .eq("email", email)
        .maybeSingle();

    if (checkError) {
        return res.status(500).json({
            success: false,
            message: "Gagal memeriksa email"
        });
    }

    if (existingUser) {
        return res.status(409).json({
            success: false,
            message: "Email sudah terdaftar"
        });
    }

    // Hash password
    const hashedPassword = await bcrypt.hash(password, 10);

    // Simpan user
    const { data, error } = await supabase
        .from("users")
        .insert({
            name: name,
            email: email,
            password: hashedPassword
        })
        .select("id, name, email, created_at");

    if (error) {
        return res.status(500).json({
            success: false,
            message: "Gagal mendaftarkan user"
        });
    }

    res.status(201).json({
        success: true,
        message: "User berhasil didaftarkan",
        data: data
    });
});

app.post("/api/login", async (req, res) => {
    const { email, password } = req.body;

    // Validasi input
    if (!email || !password) {
        return res.status(400).json({
            success: false,
            message: "Email dan password wajib diisi"
        });
    }

    // Cari user berdasarkan email
    const { data, error } = await supabase
        .from("users")
        .select("*")
        .eq("email", email)
        .single();

    // User tidak ditemukan
    if (error || !data) {
        return res.status(401).json({
            success: false,
            message: "Email atau password salah"
        });
    }

    // Bandingkan password
    const passwordMatch = await bcrypt.compare(
        password,
        data.password
    );

    if (!passwordMatch) {
        return res.status(401).json({
            success: false,
            message: "Email atau password salah"
        });
    }

    // Buat JWT
    const token = jwt.sign(
        {
            id: data.id,
            email: data.email
        },
        process.env.JWT_SECRET,
        {
            expiresIn: "1h"
        }
    );

    res.json({
        success: true,
        message: "Login berhasil",
        token: token,
        data: {
            id: data.id,
            name: data.name,
            email: data.email
        }
    });
});

app.get("/api/profile", verifyToken, async (req, res) => {
    const { data, error } = await supabase
        .from("users")
        .select("id, name, email, created_at")
        .eq("id", req.user.id)
        .single();

    if (error || !data) {
        return res.status(404).json({
            success: false,
            message: "User tidak ditemukan"
        });
    }

    res.json({
        success: true,
        message: "Data profile berhasil diambil",
        data: data
    });
});

module.exports = app;