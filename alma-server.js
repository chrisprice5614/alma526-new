require("dotenv").config() // Makes it so we can access .env file
const jwt = require("jsonwebtoken")//npm install jsonwebtoken dotenv
const bcrypt = require("bcrypt") //npm install bcrypt
const cookieParser = require("cookie-parser")//npm install cookie-parser
const express = require("express")//npm install express
const db = require("better-sqlite3")("data-alma.db") //npm install better-sqlite3
const body_parser = require("body-parser")
const path = require('path');
const nodemailer = require("nodemailer")
const mammoth = require('mammoth');
const multer = require("multer")
const sharp = require('sharp');
const fs = require("fs");
const fileStorageEngine = multer.diskStorage({
  destination: (req, file, cb) => {
    const mime = file.mimetype;
    if (mime === 'audio/mpeg') {
      cb(null, './public/audio');
    } else {
      cb(null, './public/img');
    }
  },
  filename: (req, file, cb) => {
    const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1e9);
    const ext = mimeExtension(file.mimetype);
    cb(null, `${uniqueSuffix}.${ext}`);
  }
});

// Helper to ensure consistent extension naming
function mimeExtension(mime) {
  const map = {
    'image/jpeg': 'jpg',
    'image/png': 'png',
    'video/mp4': 'mp4',
    'audio/mpeg': 'mp3'
  };
  return map[mime] || 'file';
}

const upload = multer({
  storage: fileStorageEngine,
  fileFilter: (req, file, cb) => {
    const allowedTypes = [
      'video/mp4',
      'image/jpeg',
      'image/png',
      'audio/mpeg', // mp3
      'application/vnd.openxmlformats-officedocument.wordprocessingml.document' // .docx
    ];

    if (allowedTypes.includes(file.mimetype)) {
      cb(null, true);
    } else {
      cb(new Error('Unsupported file type'), false);
    }
  }
});

const fileSizeLimiter = (req, res, next) => {
  const file = req.file;
  if (!file) return next();

  const limits = {
    'image/jpeg': 24 * 1024 * 1024,
    'image/png': 24 * 1024 * 1024,
    'video/mp4': 24 * 1024 * 1024,
    'audio/mpeg': 24 * 1024 * 1024
  };

  const limit = limits[file.mimetype];
  if (limit && file.size > limit) {
    return res.status(400).json({
      error: `File too large. Limit is ${limit / (1024 * 1024)}MB.`
    });
  }

  next();
};

module.exports = { upload, fileSizeLimiter };

const stripHtml = (html) => html.replace(/<[^>]+>/g, '');

async function sendEmail(to, subject, html) {
    let transporter = nodemailer.createTransport({
        host: "smtp.gmail.com",
        port: 465,
        secure: true,
        auth: {
            user: process.env.MAILNAME,
            pass: process.env.MAILSECRET
        },
        tls: {
            rejectUnauthorized: false
        }
    });


    let info = await transporter.sendMail({
        from: '"Chris Price Music" <info@chrispricemusic.net>',
        to: to,
        subject: subject,
        html: `<html>
        <head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Echo of Me – Email</title>
  <link rel="stylesheet" href="https://use.typekit.net/ayz5zyc.css"> <!-- Owners Text -->
  <style>
    html, body {
      margin: 0;
      padding: 0;
      background: #fff;
      color: #000;
      font-family: "owners-text", sans-serif;
      line-height: 1.6;
    }

    a {
      color: #000;
      text-decoration: none;
      font-weight: bold;
    }

    a:hover {
      text-decoration: underline;
    }

    header {
      text-align: center;
      padding: 32px 16px 16px;
    }

    header img {
      max-width: 180px;
      height: auto;
    }

    main {
      padding: 0 16px;
      max-width: 600px;
      margin: 0 auto;
    }

    footer {
      text-align: center;
      padding: 32px 16px;
      border-top: 1px solid #000;
      font-size: 14px;
    }

    h1, h2, h3 {
      font-weight: 600;
      margin-bottom: 12px;
    }

    p {
      margin-bottom: 16px;
    }

    hr {
      border: none;
      border-top: 1px solid #000;
      margin: 32px auto;
      width: 80%;
    }
  </style>
</head>
<body>
  <header>
  </header>

  <main>
    ${html}
  </main>

  <hr>

  <footer>
    <a href="https://alma526.com">alma526.com</a><br>
    Echo of Me Podcasts
  </footer>
</body>

    </html>
    `

    })

}

function slugify(title) {
  return title
    .toLowerCase()
    .replace(/\s+/g, '-')           // replace spaces with dashes
    .replace(/[^\w\-]+/g, '')       // remove special characters
    .replace(/\-\-+/g, '-')         // collapse multiple dashes
    .replace(/^-+|-+$/g, '');       // trim dashes from start/end
}

db.pragma("journal_mode = WAL") //Makes it faster
const createTables = db.transaction(() => {
    db.prepare(
        `
        CREATE TABLE IF NOT EXISTS transcripts (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        title STRING,
        content STRING,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        hero STRING,
        spotify STRING,
        catagory STRING,
        slug STRING
        )
        `
    ).run()

    db.prepare(
      `
      CREATE TABLE IF NOT EXISTS blogs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        title TEXT,
        content TEXT,
        hero TEXT,
        slug TEXT,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
      );
      `
    ).run()
})

createTables();


const app = express()
app.use(express.json())
app.set("view engine", "ejs")
app.set("views", path.join(__dirname, "views"));
app.use(express.static("public")) //Using public folder
app.use(cookieParser())
app.use(express.static('/public'));
app.use(express.urlencoded({ extended: true }));
app.use(express.json());
const axios = require("axios");
app.use(body_parser.json())

app.use(function (req, res, next) {


    try {
        const decoded = jwt.verify(req.cookies.alma, process.env.JWTSECRET)
        req.user = decoded
    } catch {
        req.user = false
    }

    res.locals.user = req.user;

    next()
})

function mustBeLoggedIn(req, res, next){
    if(req.user) {
        return next()
    }
    else
    {
        return res.redirect("/")
    }
}

app.get("/", (req,res) => {
    return res.render("index")
})

app.get("/contact-us", (req,res) => {
    return res.render("contact")
})

app.get("/can-you-feel-so-now", (req,res) => {
    const podcastName = "Can You Feel So Now?"
    const podcastDescription = "Conversations with very-recently returned missionaries of the Church of Jesus Christ of Latter-day Saints discussing changes of heart, spiritual growth, change, and challenges from their missions.To help you remember the feelings brought on by connecting with God that inspired you to make enduring positive changes."
    const podcastSpotify = "https://open.spotify.com/embed/show/6MtfyopS7SlImtUcelsdlG?utm_source=generator"
    const podcastEpisodes = "https://redcircle.com/shows/b53457c8-930e-45c1-b31c-ba2089abba03"

    const transcripts = db.prepare("SELECT * FROM transcripts WHERE catagory = ? ORDER BY created_at DESC").all("can")

    return res.render("podcast-list", {podcastName, podcastDescription, podcastSpotify, podcastEpisodes, transcripts})
})

app.get("/called-to-the-work", (req,res) => {
    const podcastName = "Called to the Work"
    const podcastDescription = "An interview with newly-called missionaries of the Church of Jesus Christ of Latter-day Saints. These missionaries have received their calls and assignments, but have not yet reported to the Missionary Training Center. It is to set the tone for their mission and to serve as a precursor for their follow-up interview 18 - 24 months later on the Can You Feel So Now? Podcast."
    const podcastSpotify = "https://open.spotify.com/embed/show/6NzspqjkELJLkmrtD8kQhV?utm_source=generator"
    const podcastEpisodes = "https://redcircle.com/shows/4f55f786-76b4-4cf4-a0eb-325802e6d029"

    const transcripts = db.prepare("SELECT * FROM transcripts WHERE catagory = ? ORDER BY created_at DESC").all("called")

    return res.render("podcast-list", {podcastName, podcastDescription, podcastSpotify, podcastEpisodes, transcripts})
})


app.post("/login", (req,res) => {
    const matchOrNot = bcrypt.compareSync(req.body.password, process.env.ADMIN_PASSWORD_HASH);

    if(matchOrNot)
    {
        const ourTokenValue = jwt.sign({exp: Math.floor(Date.now() / 1000) + (60*60*24)}, process.env.JWTSECRET) //Creating a token for logging in

        res.cookie("alma",ourTokenValue, {
            httpOnly: true,
            secure: true,
            sameSite: "strict",
            maxAge: 1000 * 60 * 60 * 24
        }) //name, string to remember,

        return res.redirect("/admin")
    }
    else
    {
        return res.redirect("/admin")
    }
})

app.get("/steadfast-in-christ", (req,res) => {
    const podcastName = "Steadfast in Christ"
    const podcastDescription = "Conversations with recent converts to the Church of Jesus Christ of Latter-day Saints. We explore the individual's journey to their decision to being baptized; their experience of baptism and confirmation; their journey in the faith since their baptism; and their hopes for their life moving forward."
    const podcastSpotify = "https://open.spotify.com/embed/show/6E110rPHH8MiSIzXFAvCfN?utm_source=generator"
    const podcastEpisodes = "https://redcircle.com/shows/c31dabee-6577-4873-9e2d-91f86971d8bf"

    const transcripts = db.prepare("SELECT * FROM transcripts WHERE catagory = ? ORDER BY created_at DESC").all("stead")

    return res.render("podcast-list", {podcastName, podcastDescription, podcastSpotify, podcastEpisodes, transcripts})
})

app.get("/view-transcript/:slug", (req,res) => {
    const transcript = db.prepare("SELECT * FROM transcripts WHERE slug = ?").get(req.params.slug)

    return res.render("podcast", {transcript})
})


app.post("/contact", async (req,res) => {

    const { name, email, message } = req.body;
    const token = req.body["g-recaptcha-response"];

  if (!token) {
    return res.render("contact", {error: "CAPTCHA verification failed"});
  }

  try {
    const response = await axios.post(
      `https://www.google.com/recaptcha/api/siteverify?secret=${process.env.GOOGLEKEY}&response=${token}`
    );

    if (!response.data.success) {
      return res.render("contact", {error: "CAPTCHA verification failed"});
    }

    const html = `
        <h1>Contact Form</h1><br>
        <h2>Contact Info</h2><br>
        <p><strong>Name:</strong> ${name}</p><br>
        <p><strong>Email:</strong> <a href="mailto:${email}">${email}</a></p><br>
        <h2>Message</h2><br>
        <p>${message.replace(/\n/g, '<br>')}</p><br>
    `;

    sendEmail("chrisprice5614@gmail.com","Contact Form",html);

    return res.redirect("thank-you")

    } catch (err) {
    return res.render("contact", {error: "CAPTCHA verification failed"});
  }
})

app.get("/edit-transcripts", mustBeLoggedIn, (req,res) => {
    const transcripts = db.prepare("SELECT * FROM transcripts ORDER BY created_at DESC").all();
    return res.render("edit-transcripts", {transcripts})
})

app.get("/add-transcript/" ,mustBeLoggedIn, (req,res) => {
    return res.render("add-transcript")
})

app.post('/add-transcript', mustBeLoggedIn, upload.single('hero'), fileSizeLimiter, (req, res) => {
  try {
    const { title, spotify, content, catagory } = req.body;
    const hero = req.file ? req.file.filename : null;

    if (!title || !spotify || !content || !catagory || !hero) {
      return res.status(400).send('Missing required fields');
    }

    const slug = slugify(title);

    db.prepare(`
      INSERT INTO transcripts (title, content, hero, spotify, catagory, slug)
      VALUES (?, ?, ?, ?, ?, ?)
    `).run(title, content, hero, spotify, catagory, slug);

    res.redirect('/edit-transcripts');
  } catch (err) {
    console.error('Error adding transcript:', err);
    res.status(500).send('Server error');
  }
});

app.get("/edit-transcript/:id", mustBeLoggedIn, (req,res) => {
    const transcript = db.prepare("SELECT * FROM transcripts WHERE id = ?").get(req.params.id);

    if(!transcript)
        return res.redirect("/edit-transcripts")

    return res.render("edit-transcript", {transcript})
})

app.post('/edit-transcript/:id', mustBeLoggedIn, upload.single('hero'), fileSizeLimiter, (req, res) => {
  try {
    const { title, spotify, content, catagory } = req.body;

    if (!title || !spotify || !content || !catagory) {
      return res.status(400).send('Missing required fields');
    }

    const transcript = db.prepare('SELECT * FROM transcripts WHERE id = ?').get(req.params.id);
    if (!transcript) {
      return res.status(404).send('Transcript not found');
    }

    let hero = transcript.hero;

    // If a new hero image was uploaded
    if (req.file) {
      const newHero = req.file.filename;

      // Delete old hero image
      if (transcript.hero) {
        const oldPath = path.join(__dirname, 'public', 'img', transcript.hero);
        fs.unlink(oldPath, err => {
          if (err) console.warn('Failed to delete old image:', err);
        });
      }

      hero = newHero;
    }

    const slug = slugify(title);

    db.prepare(`
      UPDATE transcripts
      SET title = ?, spotify = ?, content = ?, catagory = ?, hero = ?, slug = ?
      WHERE id = ?
    `).run(title, spotify, content, catagory, hero, slug, req.params.id);

    res.redirect('/edit-transcripts');
  } catch (err) {
    console.error('Error updating transcript:', err);
    res.status(500).send('Server error');
  }
});

app.get("/edit-blogs", mustBeLoggedIn, (req,res) => {
  const blogs = db.prepare("SELECT * FROM blogs ORDER BY created_at DESC").all()
  return res.render("edit-blogs", {blogs})
})

app.get("/add-blog", mustBeLoggedIn, (req,res) => {
  return res.render("add-blog")
})

app.post('/add-blog', mustBeLoggedIn, upload.single('docx'), async (req, res) => {
  try {
    const docxPath = req.file.path;
    const imagesDir = './public/img/blogs/';
    if (!fs.existsSync(imagesDir)) fs.mkdirSync(imagesDir, { recursive: true });

    let hero = null;

    // Convert .docx to HTML
    const { value: html } = await mammoth.convertToHtml({ path: docxPath }, {
      convertImage: mammoth.images.inline(async (element) => {
        const ext = element.contentType.split('/')[1]; // e.g., 'jpeg'
        const filename = `blog-${Date.now()}-${Math.round(Math.random() * 1e6)}.${ext}`;
        const filepath = path.join(imagesDir, filename);

        const imageBuffer = await element.read();
        fs.writeFileSync(filepath, imageBuffer);

        if (!hero) hero = filename; // first image is the hero
        return { src: `/img/blogs/${filename}` };
      }),
    });

    // Get title from first <p> or <h1> line of HTML
    const titleMatch = html.match(/<p>(.*?)<\/p>/) || html.match(/<h1>(.*?)<\/h1>/);
    const rawTitle = titleMatch ? titleMatch[1] : `Blog-${Date.now()}`;
    const title = stripHtml(rawTitle).trim();
    const slug = slugify(title)

    // Save into DB
    db.prepare(`
      INSERT INTO blogs (title, content, hero, slug)
      VALUES (?, ?, ?, ?)
    `).run(title, html, hero, slug);

    res.redirect('/edit-blogs');
  } catch (err) {
    console.error('Error adding blog:', err);
    res.status(500).send('Failed to create blog');
  }
});

app.get("/delete-transcript/:id", mustBeLoggedIn, (req,res) => {
  const transcript = db.prepare("SELECT * FROM transcripts WHERE id = ?").get(req.params.id)

  if(!transcript)
    return res.redirect("/edit-transcripts")

  db.prepare("DELETE FROM transcripts WHERE id = ?").run(req.params.id)

  return res.redirect("/edit-transcripts")
})

app.get("/delete-blog/:id", mustBeLoggedIn, (req,res) => {
  const blog = db.prepare("SELECT * FROM blogs WHERE id = ?").get(req.params.id)

  if(!blog)
    return res.redirect("/edit-blogs")

  db.prepare("DELETE FROM blogs WHERE id = ?").run(req.params.id)

  return res.redirect("/edit-blogs")
})

app.get("/blog", (req,res) => {
  const blogs = db.prepare("SELECT * FROM blogs ORDER BY created_at DESC").all()
  return res.render("blog", {blogs})
})

app.get("/blog/:slug", (req,res) => {
  const blog = db.prepare("SELECT * FROM blogs WHERE slug = ?").get(req.params.slug)

  if(!blog)
    return res.redirect("/blog")

  return res.render("single-blog", {blog})
})

app.get("/admin", (req,res) => {
    if(!req.user)
        return res.render("login")

    return res.render("admin")
})

app.get("/thank-you", (req,res) => {
    return res.render("thank-you")
})

app.use((req, res) => {
    res.status(404).render('404');
});

app.listen(3736)


