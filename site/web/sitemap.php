<?PHP

header('Content-Type: text/xml');

echo "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n";
echo "<urlset xmlns=\"http://www.sitemaps.org/schemas/sitemap/0.9\">\n";

//index.php
echo "\t<url>\n";
echo "\t\t<loc>https://www.stigqter.com/</loc>\n";
echo "\t\t<lastmod>".date("c", filemtime("/var/www/stigqter.com/web/index.php"))."</lastmod>\n";
echo "\t\t<changefreq>monthly</changefreq>\n";
echo "\t\t<priority>1.0</priority>\n";
echo "\t</url>\n";

flush();

if ($handle = opendir("/var/www/stigqter.com/web/stigs"))
{
	while (false !== ($file = readdir($handle)))
	{
		if (strlen($file) < 5)
			continue;
		if (substr($file, strlen($file) - 4) != "html")
			continue;
		echo "\t<url>\n";
		$bn = basename($file);
		echo "\t\t<loc>https://www.stigqter.com/stigs/".$bn."</loc>\n";
		echo "\t\t<lastmod>".date("c", filemtime("/var/www/stigqter.com/web/stigs/".$bn))."</lastmod>\n";
		echo "\t\t<changefreq>yearly</changefreq>\n";
		echo "\t\t<priority>0.8</priority>\n";
		echo "\t</url>\n";
		flush();
	}
}

echo "</urlset>\n";
?>
