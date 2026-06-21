const asyncHandler = require("../utils/asyncHandler");
const { BadRequestError } = requie('../utils/error');
const scheduleService = require('../services/schedule.service');


exports.createSchedule = asyncHandler(async (req, res) => {
    const { trainId, departureDate } = req.body;

    if (!trainId || !departureDate) {
        throw new BadRequestError('trainId and departureDate required');
    }

    const schedule = await scheduleService.createSchedule({ trainId, dapartureDate });

    return res.status(201).json({
        success: true,
        message: "Train schedule created successfully",
        data : schedule
    })
})


exports.getAllSchedules = asyncHandler(async(req, res) =>{

})

exports.getScheduleById = asyncHandler(async(req, res) =>{
     
})