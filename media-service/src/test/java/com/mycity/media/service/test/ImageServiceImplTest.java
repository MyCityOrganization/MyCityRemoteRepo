package com.mycity.media.service.test;

import com.mycity.media.entity.Images;
import com.mycity.media.helper.CloudinaryHelper;
import com.mycity.media.repository.ImageServiceRepository;
import com.mycity.media.serviceImpl.ImageServiceImpl;
import com.mycity.shared.mediadto.AboutPlaceImageDTO;
import com.mycity.shared.mediadto.ImageDTO;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.mockito.InjectMocks;
import org.mockito.Mock;

import org.springframework.web.multipart.MultipartFile;

import java.util.List;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

import org.mockito.MockitoAnnotations;

class ImageServiceImplTest {

    @Mock
    private CloudinaryHelper cloudinaryHelper;

    @Mock
    private ImageServiceRepository imageServiceRepository;

    @InjectMocks
    private ImageServiceImpl imageService;

    @BeforeEach
    void setUp() {
        MockitoAnnotations.openMocks(this);
    }

    @Test
    void testUploadImageForPlaces() {
        MultipartFile mockFile = mock(MultipartFile.class);
        when(cloudinaryHelper.saveImage(mockFile)).thenReturn("http://image.url");

        imageService.uploadImageForPlaces(mockFile, 1L, "PlaceName", "Category", "ImageName");

        ArgumentCaptor<Images> captor = ArgumentCaptor.forClass(Images.class);
        verify(imageServiceRepository).save(captor.capture());

        Images saved = captor.getValue();
        assertEquals("http://image.url", saved.getImageUrl());
        assertEquals("PlaceName", saved.getPlaceName());
        assertEquals("Category", saved.getCategory());
        assertEquals("ImageName", saved.getImageName());
        assertEquals(1L, saved.getPlaceId());
    }

//    @Test
//    void testFetchImage() {
//        Images image = new Images();
//        image.setImageId(1L);
//        image.setImageUrl("http://image.url");
//        image.setCategory("Nature");
//        image.setPlaceName("Paris");
//        image.setPlaceId(123L);
//
//        when(imageServiceRepository.findById(1L)).thenReturn(Optional.of(image));
//
//        ImageDTO dto = imageService.fetchImage(1L);
//
//        assertEquals("http://image.url", dto.getImageUrl());
//        assertEquals("Nature", dto.getCategory());
//        assertEquals("Paris", dto.getPlaceName());
//        assertEquals(123L, dto.getPlaceId());
//    }

//    @Test
//    void testFetchImage_NotFound() {
//        when(imageServiceRepository.findById(2L)).thenReturn(Optional.empty());
//        assertThrows(RuntimeException.class, () -> imageService.fetchImage(2L));
//    }

    @Test
    void testGetAboutPlaceImagesByPlaceId() {
        Images img1 = new Images();
        img1.setImageUrl("url1");
        img1.setImageName("name1");

        Images img2 = new Images();
        img2.setImageUrl("url2");
        img2.setImageName("name2");

        when(imageServiceRepository.findImagesByPlaceId(1L)).thenReturn(List.of(img1, img2));

        List<AboutPlaceImageDTO> result = imageService.getAboutPlaceImages(1L);

        assertEquals(2, result.size());
        assertEquals("url1", result.get(0).getImageUrl());
        assertEquals("name1", result.get(0).getImageName());
    }

    @Test
    void testGetAboutPlaceImagesByPlaceName() {
        Images img = new Images();
        img.setImageUrl("url1");
        img.setImageName("placeimagemain");

        Images img2 = new Images();
        img2.setImageUrl("url2");
        img2.setImageName("other");

        when(imageServiceRepository.findImagesByPlaceName("Paris")).thenReturn(List.of(img, img2));

        List<AboutPlaceImageDTO> result = imageService.getAboutPlaceImages("Paris");

        assertEquals(1, result.size());
        assertEquals("url1", result.get(0).getImageUrl());
    }

    @Test
    void testDeleteImage_Success() {
        when(imageServiceRepository.findImageIdsByPlaceId(1L)).thenReturn(List.of(101L));
        when(imageServiceRepository.findById(101L)).thenReturn(Optional.of(new Images()));

        String result = imageService.deleteImage(1L);

        verify(imageServiceRepository).deleteById(101L);
        assertTrue(result.contains("have been deleted"));
    }

    @Test
    void testDeleteImage_NoImagesFound() {
        when(imageServiceRepository.findImageIdsByPlaceId(1L)).thenReturn(List.of());

        Exception exception = assertThrows(IllegalArgumentException.class,
                () -> imageService.deleteImage(1L));

        assertEquals("No images found for PlaceId: 1", exception.getMessage());
    }

    @Test
    void testDeleteImage_ImageNotFoundById() {
        when(imageServiceRepository.findImageIdsByPlaceId(1L)).thenReturn(List.of(999L));
        when(imageServiceRepository.findById(999L)).thenReturn(Optional.empty());

        Exception exception = assertThrows(IllegalArgumentException.class,
                () -> imageService.deleteImage(1L));

        assertTrue(exception.getMessage().contains("not found"));
    }
}
