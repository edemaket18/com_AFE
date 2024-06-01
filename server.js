const express = require('express');
const mongoose = require('mongoose');
const bodyParser = require('body-parser');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
const User = require('./models/User');
const CV = require('./models/CV');
const app = express();

app.use(bodyParser.json());

mongoose.connect('mongodb://localhost:27017/', { useNewUrlParser: true, useUnifiedTopology: true });

// Middleware pour authentification
function authenticateToken(req, res, next) {
  const token = req.header('Authorization').replace('Bearer ', '');
  if (!token) return res.status(401).send({ error: 'Access denied' });
  try {
    const verified = jwt.verify(token, 'admin');
    req.user = verified;
    next();
  } catch (err) {
    res.status(400).send({ error: 'Invalid token' });
  }
}

// Routes
app.post('/register', async (req, res) => {
  const { name, email, password } = req.body;
  const hashedPassword = await bcrypt.hash(password, 10);
  const user = new User({ name, email, password: hashedPassword });
  await user.save();
  const token = jwt.sign({ userId: user._id }, 'admin');
  res.send({ token });
});

app.post('/login', async (req, res) => {
  const { email, password } = req.body;
  const user = await User.findOne({ email });
  if (!user || !await bcrypt.compare(password, user.password)) {
    return res.status(422).send({ error: 'Invalid email or password' });
  }
  const token = jwt.sign({ userId: user._id }, 'admin');
  res.send({ token });
});

app.post('/cv', authenticateToken, async (req, res) => {
  const { file } = req.body;  // Assumes file is a base64 encoded string
  const cv = new CV({ userId: req.user.userId, file, state: 'En attente', comments: '' });
  await cv.save();
  res.send(cv);
});

app.get('/cvs', authenticateToken, async (req, res) => {
  const cvs = await CV.find({ userId: req.user.userId });
  res.send(cvs);
});

app.put('/cv/:id', authenticateToken, async (req, res) => {
  const { state, comments } = req.body;
  const cv = await CV.findByIdAndUpdate(req.params.id, { state, comments }, { new: true });
  res.send(cv);
});

app.listen(3000, () => {
  console.log('Server is running on port 3000');
});

// server.js (ajouter ces routes)
app.get('/profile', authenticateToken, async (req, res) => {
    const user = await User.findById(req.user.userId);
    res.send(user);
  });
  
  app.put('/profile', authenticateToken, async (req, res) => {
    const { name, academicInfo } = req.body;
    const user = await User.findByIdAndUpdate(req.user.userId, { name, academicInfo }, { new: true });
    res.send(user);
  });
  
  function authenticateToken(req, res, next) {
    const token = req.header('Authorization').replace('Bearer ', '');
    if (!token) return res.status(401).send({ error: 'Access denied' });
    try {
      const verified = jwt.verify(token, 'admin');
      req.user = verified;
      next();
    } catch (err) {
      res.status(400).send({ error: 'Invalid token' });
    }
  }

  const CvSchema = new mongoose.Schema({
    userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
    file: String,
    date: { type: Date, default: Date.now },
    state: String,
    comments: String
  });
  
  const CV = mongoose.model('CV', CvSchema);
  
  app.post('/cv', authenticateToken, async (req, res) => {
    const { file } = req.body;  // Assumes file is a base64 encoded string
    const cv = new CV({ userId: req.user.userId, file, state: 'En attente', comments: '' });
    await cv.save();
    res.send(cv);
  });
  
  app.get('/cvs', authenticateToken, async (req, res) => {
    const cvs = await CV.find({ userId: req.user.userId });
    res.send(cvs);
  });
  
  app.put('/cv/:id', authenticateToken, async (req, res) => {
    const { state, comments } = req.body;
    const cv = await CV.findByIdAndUpdate(req.params.id, { state, comments }, { new: true });
    res.send(cv);
  });

  
  const ConventionSchema = new mongoose.Schema({
    userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
    info: String,
    state: String,
    comments: String
  });
  
  const Convention = mongoose.model('Convention', ConventionSchema);
  
  app.post('/convention', authenticateToken, async (req, res) => {
    const { info } = req.body;
    const convention = new Convention({ userId: req.user.userId, info, state: 'En attente', comments: '' });
    await convention.save();
    res.send(convention);
  });
  
  app.get('/conventions', authenticateToken, async (req, res) => {
    const conventions = await Convention.find({ userId: req.user.userId });
    res.send(conventions);
  });
  
  app.put('/convention/:id', authenticateToken, async (req, res) => {
    const { state, comments } = req.body;
    const convention = await Convention.findByIdAndUpdate(req.params.id, { state, comments }, { new: true });
    res.send(convention);
  });

  
  const OfferSchema = new mongoose.Schema({
    title: String,
    description: String,
    type: String,
    field: String,
    location: String,
    publicationDate: { type: Date, default: Date.now },
    companyId: mongoose.Schema.Types.ObjectId
  });
  
  const Offer = mongoose.model('Offer', OfferSchema);
  
  app.post('/offer', authenticateToken, async (req, res) => {
    const { title, description, type, field, location, companyId } = req.body;
    const offer = new Offer({ title, description, type, field, location, companyId });
    await offer.save();
    res.send(offer);
  });
  
  app.get('/offers', async (req, res) => {
    const offers = await Offer.find();
    res.send(offers);
  });
  
  app.get('/offer/:id', async (req, res) => {
    const offer = await Offer.findById(req.params.id);
    res.send(offer);
  });
  