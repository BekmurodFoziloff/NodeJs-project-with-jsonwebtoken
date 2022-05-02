const { Schema, model } = require('mongoose')

const itemSchema = new Schema({
    img: {
        type: String,
        required: true
    },
    head: {
        type: String,
        required: true
    },
    text: {
        type: String,
        required: true
    },
    userId: {
        type: Schema.Types.ObjectId,
        ref: 'User',
        required: true
    },
    createdAt: {
        type: Date,
        default: Date.now(),
        required: true
    },
    updatedAt: {
        type: Date,
        default: Date.now(),
        required: true
    }
})

module.exports = model('New', itemSchema)