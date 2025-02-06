require('dotenv').config();
const express = require('express');
const cors = require('cors');
const mongoose = require('mongoose');
const authRoutes = require('./routes/authRoutes');
const checkInRoutes = require('./routes/checkInRoutes');

const app = express();
app.use(express.json());
app.use(cors());



// MongoDB Connection
mongoose.connect(process.env.MONGO_URI, {
});

app.use('/auth', authRoutes);
app.use('/check', checkInRoutes);

const PORT = process.env.PORT;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));