/**
 * This file is hereby placed into the Public Domain. This means anyone is
 * free to do whatever they wish with this file.
 */
package mil.nga.giat.process.elasticsearch;

import java.awt.image.Raster;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.IntStream;

import org.geotools.coverage.grid.GridCoverage2D;
import org.geotools.data.simple.SimpleFeatureCollection;
import org.geotools.feature.DefaultFeatureCollection;
import org.geotools.feature.simple.SimpleFeatureBuilder;
import org.geotools.feature.simple.SimpleFeatureTypeBuilder;
import org.opengis.feature.simple.SimpleFeatureType;

public class TestUtil {

    public static SimpleFeatureCollection createAggregationFeatures(List<Map<String,Object>> data) {
        final SimpleFeatureTypeBuilder builder = new SimpleFeatureTypeBuilder();
        builder.setName( "testType" );
        builder.add("_aggregation", HashMap.class );
        builder.add("aString", String.class );
        final SimpleFeatureType featureType = builder.buildFeatureType();
        final DefaultFeatureCollection collection = new DefaultFeatureCollection();
        final SimpleFeatureBuilder featureBuilder = new SimpleFeatureBuilder(featureType);
        data.stream().forEach(item -> {
            item.keySet().stream().forEach(key -> {
                featureBuilder.set(key, item.get(key));
            });
            collection.add(featureBuilder.buildFeature(null));
        });
        return collection;
    }

    public static float[][] getGrid(GridCoverage2D coverage) {
        Raster data = coverage.getRenderedImage().getData();
        float[][] grid = new float[data.getHeight()][data.getWidth()];
        IntStream.range(0, data.getHeight()).forEach(i-> {
            IntStream.range(0, data.getWidth()).forEach(j-> {
                grid[i][j] = data.getPixel(j,i,new float[1])[0];
            });
        });
        return grid;
    }

    public static String toString(float[][] grid) {
        return Arrays.deepToString(grid).replace("], ", "]\n ");
    }

}