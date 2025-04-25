package com.mycity.shared.placedto;

import java.time.LocalDate;

import com.mycity.shared.timezonedto.TimezoneDTO;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@NoArgsConstructor
@AllArgsConstructor
public class PlaceDTO 
{
    private String name;
    private String about;
    private String history;
    private TimezoneDTO timezone;
    private LocalDate postedOn;
    private String category;
    private Double latitude;
    private Double longitude;
    private String  placeDistrict;
}

